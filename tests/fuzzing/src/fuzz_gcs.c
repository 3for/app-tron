#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "apdu_constants.h"
#include "cmd_field.h"
#include "cmd_tx_info.h"
#include "gcs_calldata_bridge.h"
#include "gcs_signing_context.h"
#include "tlv_apdu.h"
#include "tron_tx_stream.h"
#include "tx_ctx.h"
#include "parse.h"
#include "shared_context.h"

void init_tip712_fuzz_environment(void);
void fuzz_set_settings(uint8_t value);
void reset_app_context(void);

static void assert_asset_type_isolation(void) {
#ifndef TARGET_NANOS
    static const uint8_t nft_address[ADDRESS_LENGTH] = {
        0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
        0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    };
    const uint8_t index = MAX_ASSETS - 1U;

    memcpy(tmpCtx.transactionContext.extraInfo[index].nft.contractAddress,
           nft_address,
           sizeof(nft_address));
    tmpCtx.transactionContext.assetSet[index] = true;
    tmpCtx.transactionContext.assetKind[index] = ASSET_KIND_NFT;
    if ((get_token_info_by_addr(nft_address) != NULL) ||
        (get_nft_info_by_addr(nft_address) == NULL)) {
        __builtin_trap();
    }
#endif
}

/*
 * Byte stream format:
 *   settings (1 byte), followed by zero or more APDU records:
 *   ins (1), p1 (1), p2 (1), payload length (1), payload (length).
 *
 * The supported instructions form the complete Generic Clear Signing flow:
 * SIGN_GCS/STORE streams and parks a TriggerSmartContract, GTP_TRANSACTION_INFO
 * and GTP_FIELD provide its signed descriptors, and SIGN_GCS/START_FLOW checks
 * the field hash and starts review. Keeping the APDU framing under fuzzer
 * control also covers restarts, invalid ordering and truncated streams.
 */
static void fuzz_gcs_apdu_stream(const uint8_t *data, size_t size) {
    uint8_t payload[UINT8_MAX];

    while (size >= 4U) {
        const uint8_t ins = data[0];
        const uint8_t p1 = data[1];
        const uint8_t p2 = data[2];
        size_t payload_len = data[3];
        data += 4U;
        size -= 4U;

        if (payload_len > size) {
            payload_len = size;
        }
        if (payload_len != 0U) {
            memcpy(payload, data, payload_len);
        }

        switch (ins) {
            case INS_SIGN_GCS:
                (void) handleSignGcs(p1, p2, payload, (uint16_t) payload_len);
                break;
            case INS_GTP_TRANSACTION_INFO:
                if (handle_tx_info(p1, p2, (uint8_t) payload_len, payload) != SWO_SUCCESS) {
                    reset_app_context();
                }
                break;
            case INS_GTP_FIELD:
                if (handle_field(p1, p2, (uint8_t) payload_len, payload) != SWO_SUCCESS) {
                    reset_app_context();
                }
                break;
            default:
                break;
        }

        data += payload_len;
        size -= payload_len;
    }
}

/* Complete the firmware reset semantics for this target's GCS-owned globals. */
void fuzz_reset_extra_context(void) {
    tlv_apdu_reset();
    tron_tx_stream_free();
    gcs_bridge_abort();
    gcs_cleanup();
    gcs_signing_context_cleanup();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_tip712_fuzz_environment();
    assert_asset_type_isolation();
    if (size != 0U) {
        fuzz_set_settings(*data++);
        size--;
        fuzz_gcs_apdu_stream(data, size);
    }
    fuzz_reset_extra_context();
    return 0;
}
