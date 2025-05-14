#include "os_utils.h"
#include "os_pic.h"
#include "network.h"
#include "network_info.h"
#include "shared_context.h"
#include "common_utils.h"

const char g_unknown_ticker[] = "???";

// Mapping of chain ids to networks.
static const network_info_t NETWORK_MAPPING[] = {
    {.chain_id = 1151668124, .name = "TRON", .ticker = "TRX"},
};

static const network_info_t *get_network_from_chain_id(const uint64_t *chain_id) {
    if (*chain_id != 0) {
#ifdef HAVE_DYNAMIC_NETWORKS
        // Look if the network is available
        for (size_t i = 0; i < MAX_DYNAMIC_NETWORKS; i++) {
            if (DYNAMIC_NETWORK_INFO[i].chain_id == *chain_id) {
                PRINTF("[NETWORK] - Found dynamic \"%s\" in slot %u\n",
                       DYNAMIC_NETWORK_INFO[i].name,
                       i);
                return (const network_info_t *) &DYNAMIC_NETWORK_INFO[i];
            }
        }
#endif  // HAVE_DYNAMIC_NETWORKS

        // Fallback to hardcoded table
        for (size_t i = 0; i < ARRAYLEN(NETWORK_MAPPING); i++) {
            if (NETWORK_MAPPING[i].chain_id == *chain_id) {
                PRINTF("[NETWORK] - Fallback on hardcoded list. Found %s\n",
                       NETWORK_MAPPING[i].name);
                return (const network_info_t *) &NETWORK_MAPPING[i];
            }
        }
    }
    return NULL;
}

const char *get_network_name_from_chain_id(const uint64_t *chain_id) {
    const network_info_t *net = get_network_from_chain_id(chain_id);

    if (net == NULL) {
        return NULL;
    }
    return PIC(net->name);
}

const char *get_network_ticker_from_chain_id(const uint64_t *chain_id) {
    const network_info_t *net = get_network_from_chain_id(chain_id);

    if (net == NULL) {
        return NULL;
    }
    return PIC(net->ticker);
}

bool chain_is_ethereum_compatible(const uint64_t *chain_id) {
    return get_network_from_chain_id(chain_id) != NULL;
}

// Returns the chain ID. Defaults to 0 if txType was not found (For TX).
uint64_t get_tx_chain_id(void) {
    uint64_t chain_id = 0;

    switch (txContext.txType) {
        case LEGACY:
            chain_id = u64_from_BE(txContext.content->v, txContext.content->vLength);
            break;
        case EIP2930:
        case EIP1559:
#ifdef HAVE_EIP7702
        case EIP7702:
#endif  // HAVE_EIP7702
            chain_id = u64_from_BE(tmpContent.txContent.chainID.value,
                                   tmpContent.txContent.chainID.length);
            break;
        default:
            PRINTF("Txtype `%d` not supported while generating chainID\n", txContext.txType);
            break;
    }
    return chain_id;
}

const char *get_displayable_ticker(const uint64_t *chain_id, const chain_config_t *chain_cfg) {
    const char *ticker = get_network_ticker_from_chain_id(chain_id);

    if (ticker == NULL) {
        if (*chain_id == chain_cfg->chainId) {
            ticker = chain_cfg->coinName;
        } else {
            ticker = g_unknown_ticker;
        }
    }
    return ticker;
}

/**
 * Checks whether the app can support the given chain ID
 *
 * - If the given chain ID is the same as the app's one
 * - If both chain IDs are present in the array of Ethereum-compatible networks
 */
bool app_compatible_with_chain_id(const uint64_t *chain_id) {
    return ((chainConfig->chainId == *chain_id) ||
            (chain_is_ethereum_compatible(&chainConfig->chainId) &&
             chain_is_ethereum_compatible(chain_id)));
}
