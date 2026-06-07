#include "os_utils.h"
#include "os_pic.h"
#include "network.h"
#include "shared_context.h"
#include "common_utils.h"
#include "app_errors.h"

const char g_unknown_ticker[] = "???";

// Mapping of chain ids to networks.
// TRON holds the mainnet plus the Nile testnet entry. The lookup machinery is
// kept identical to app-ethereum so the two implementations can be diffed/
// audited side by side.
static const network_info_t NETWORK_MAPPING[] = {
    {.chain_id = TRON_MAINNET_CHAINID, .name = "Tron", .ticker = "TRX"},
    {.chain_id = TRON_NILE_CHAINID, .name = "Tron Nile", .ticker = "TRX"},
};

/**
 * @brief Find a dynamically loaded network by its chain ID
 *
 * TRON does not support dynamically-provided networks (no
 * PROVIDE_NETWORK_CONFIGURATION command), so there is never a dynamic list to
 * search and this always returns NULL. Kept for API parity with app-ethereum.
 *
 * @param[in] chain_id The chain ID to search for
 * @return Pointer to network_info_t if found, NULL otherwise
 */
network_info_t *find_dynamic_network_by_chain_id(uint64_t chain_id) {
    UNUSED(chain_id);
    return NULL;
}

static const network_info_t *get_network_from_chain_id(const uint64_t *chain_id, bool dynamic) {
    if (*chain_id != 0) {
        // Look if the network is available in dynamically loaded networks
        if (dynamic == true) {
            network_info_t *net_info = find_dynamic_network_by_chain_id(*chain_id);
            if (net_info != NULL) {
                PRINTF("[NETWORK] - Found dynamic '%s'\n", net_info->name);
                return (const network_info_t *) net_info;
            }
        }

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

static const char *get_network_ticker_from_chain_id(const uint64_t *chain_id, bool dynamic) {
    const network_info_t *net = get_network_from_chain_id(chain_id, dynamic);

    if (net == NULL) {
        return NULL;
    }
    return PIC(net->ticker);
}

const char *get_network_name_from_chain_id(const uint64_t *chain_id) {
    const network_info_t *net = get_network_from_chain_id(chain_id, true);

    if (net == NULL) {
        return NULL;
    }
    return PIC(net->name);
}

bool get_network_as_string_from_chain_id(char *out, size_t out_size, uint64_t chain_id) {
    const char *name = get_network_name_from_chain_id(&chain_id);

    if (name == NULL) {
        // No network name found so simply copy the chain ID as the network name.
        if (!u64_to_string(chain_id, out, out_size)) {
            return false;
        }
    } else {
        // Network name found, simply copy it.
        strlcpy(out, name, out_size);
    }
    return true;
}

bool get_network_as_string(char *out, size_t out_size) {
    uint64_t chain_id = get_tx_chain_id();
    return get_network_as_string_from_chain_id(out, out_size, chain_id);
}

bool chain_is_ethereum_compatible(const uint64_t *chain_id) {
    return get_network_from_chain_id(chain_id, true) != NULL;
}

// Returns the chain ID.
// TRON is a single-chain application: unlike EVM RLP transactions there is no
// per-transaction chain ID embedded in the protobuf transaction, so the network
// is always TRON mainnet.
uint64_t get_tx_chain_id(void) {
    return TRON_MAINNET_CHAINID;
}

const char *get_displayable_ticker(const uint64_t *chain_id,
                                   const chain_config_t *chain_cfg,
                                   bool dynamic) {
    const char *ticker = get_network_ticker_from_chain_id(chain_id, dynamic);

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
 * - If both chain IDs are present in the array of compatible networks
 */
bool app_compatible_with_chain_id(const uint64_t *chain_id) {
    return ((chainConfig->chainId == *chain_id) ||
            (chain_is_ethereum_compatible(&chainConfig->chainId) &&
             chain_is_ethereum_compatible(chain_id)));
}
