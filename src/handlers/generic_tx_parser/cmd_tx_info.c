#include <string.h>
#include "cmd_tx_info.h"
#include "cx.h"
#include "apdu_constants.h"
#include "gcs_memory.h"
#include "gtp_tx_info.h"
#include "tlv_apdu.h"
#include "tx_ctx.h"
#include "gcs_limits.h"
#include "gcs_signing_context.h"

static bool handle_tlv_payload(const buffer_t *buf) {
    s_tx_info_ctx ctx = {0};

    if (!verify_tx_info_authenticity(buf) ||
        ((appState == APP_STATE_SIGNING_TX) &&
         !gcs_account_descriptor(buf->size, false))) {
        return false;
    }
    /* Initialize the local crypto context before acquiring tracked heap
     * ownership. A CX exception here must not strand an allocation that is not
     * yet reachable from the global transaction-context cleanup. */
    cx_sha256_init(&ctx.struct_hash);
    ctx.tx_info = gcs_mem_calloc(sizeof(*ctx.tx_info), GCS_MEM_TX_CONTEXT);
    if (ctx.tx_info == NULL) {
        return false;
    }
    if (!handle_tx_info_struct(buf, &ctx)) {
        gcs_mem_free(ctx.tx_info);
        return false;
    }
    if (!verify_tx_info_struct(&ctx)) {
        gcs_mem_free(ctx.tx_info);
        return false;
    }
    if (!find_matching_tx_ctx(ctx.tx_info->contract_addr,
                              ctx.tx_info->selector,
                              &ctx.tx_info->chain_id)) {
        gcs_mem_free(ctx.tx_info);
        return false;
    }
    if ((get_current_tx_info() != NULL) || !process_empty_txs_before()) {
        gcs_mem_free(ctx.tx_info);
        return false;
    }
    /* Once set_tx_info_into_tx_ctx() is entered, the current tx context owns
     * ctx.tx_info even if adding a forced field later fails. */
    return set_tx_info_into_tx_ctx(ctx.tx_info);
}

uint16_t handle_tx_info(uint8_t p1, uint8_t p2, uint8_t lc, const uint8_t *payload) {
    if ((p2 != 0x00) ||
        ((p1 != P1_FIRST_CHUNK) && (p1 != P1_FOLLOWING_CHUNK))) {
        tlv_apdu_reset();
        return SWO_WRONG_P1_P2;
    }
    if ((appState != APP_STATE_SIGNING_TX) && (appState != APP_STATE_SIGNING_EIP712)) {
        PRINTF("App not in TX signing mode!\n");
        tlv_apdu_reset();
        return SWO_COMMAND_NOT_ALLOWED;
    }
    if ((appState == APP_STATE_SIGNING_TX) &&
        !gcs_account_descriptor_apdu()) {
        tlv_apdu_reset();
        return SWO_INCORRECT_DATA;
    }
    if (!tlv_from_apdu(INS_GTP_TRANSACTION_INFO,
                       p2,
                       p1 == P1_FIRST_CHUNK,
                       lc,
                       payload,
                       GCS_MAX_DESCRIPTOR_SIZE,
                       &handle_tlv_payload)) {
        return gcs_mem_take_allocation_failure() ? SWO_INSUFFICIENT_MEMORY
                                                 : SWO_INCORRECT_DATA;
    }
    return SWO_SUCCESS;
}
