#include <string.h>
#include "os.h"
#include "gcs_calldata_bridge.h"
#include "calldata.h"        // s_calldata, CALLDATA_SELECTOR_SIZE, calldata_*
#include "tx_ctx.h"          // g_parked_calldata, tx_ctx_init
#include "common_utils.h"    // INT256_LENGTH
#include "app_mem_utils.h"   // (calldata uses app mem; kept for clarity)

// TRON addresses are 21 bytes: a 0x41 mainnet prefix followed by the 20-byte
// EVM-style address. The generic_tx_parser works with 20-byte addresses.
#define TRON_ADDR_PREFIX_LEN 1

static uint8_t s_selector[CALLDATA_SELECTOR_SIZE];
static uint8_t s_selector_len;

void gcs_bridge_reset(void) {
    memset(s_selector, 0, sizeof(s_selector));
    s_selector_len = 0;
    gcs_bridge_abort();
}

void gcs_bridge_abort(void) {
    if (g_parked_calldata != NULL) {
        calldata_delete(g_parked_calldata);
        g_parked_calldata = NULL;
    }
}

bool gcs_bridge_feed_data_chunk(void *ctx,
                                const uint8_t *chunk,
                                size_t chunk_len,
                                size_t chunk_offset,
                                size_t total_len) {
    (void) ctx;

    if (chunk == NULL) {
        return false;
    }
    // The calldata must contain at least the 4-byte selector.
    if (total_len < CALLDATA_SELECTOR_SIZE) {
        PRINTF("[GCS] calldata shorter than a selector (%u)\n", (unsigned int) total_len);
        return false;
    }

    for (size_t i = 0; i < chunk_len; i++) {
        size_t off = chunk_offset + i;

        if (off < CALLDATA_SELECTOR_SIZE) {
            // Collect the selector byte by byte.
            s_selector[off] = chunk[i];
            s_selector_len = (uint8_t) (off + 1);

            // Selector complete -> allocate the parked calldata for the args.
            if (s_selector_len == CALLDATA_SELECTOR_SIZE) {
                gcs_bridge_abort();  // drop any stale parked calldata
                g_parked_calldata =
                    calldata_init(total_len - CALLDATA_SELECTOR_SIZE, s_selector);
                if (g_parked_calldata == NULL) {
                    PRINTF("[GCS] calldata_init failed\n");
                    return false;
                }
            }
        } else {
            // ABI-encoded arguments -> append into the parked calldata.
            if (g_parked_calldata == NULL) {
                return false;
            }
            uint8_t byte = chunk[i];
            if (!calldata_append(g_parked_calldata, &byte, 1)) {
                PRINTF("[GCS] calldata_append failed at offset %u\n", (unsigned int) off);
                return false;
            }
        }
    }
    return true;
}

bool gcs_bridge_finalize(const uint8_t *owner21,
                         const uint8_t *contract21,
                         uint64_t call_value,
                         uint64_t chain_id) {
    uint8_t amount[INT256_LENGTH];

    if (g_parked_calldata == NULL) {
        PRINTF("[GCS] finalize without parked calldata\n");
        return false;
    }

    // Strip the TRON 0x41 prefix: generic_tx_parser uses 20-byte addresses.
    const uint8_t *from = (owner21 != NULL) ? (owner21 + TRON_ADDR_PREFIX_LEN) : NULL;
    const uint8_t *to = (contract21 != NULL) ? (contract21 + TRON_ADDR_PREFIX_LEN) : NULL;

    // Encode the call value as a 32-byte big-endian integer (ABI uint256).
    memset(amount, 0, sizeof(amount));
    for (size_t i = 0; i < sizeof(uint64_t); i++) {
        amount[INT256_LENGTH - 1 - i] = (uint8_t) (call_value >> (8 * i));
    }

    if (!tx_ctx_init(g_parked_calldata, from, to, amount, &chain_id)) {
        PRINTF("[GCS] tx_ctx_init failed\n");
        return false;
    }
    // Ownership of the calldata has been transferred to the tx context.
    g_parked_calldata = NULL;
    return true;
}
