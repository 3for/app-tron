#include "cmd_field.h"
#include "cx.h"
#include "apdu_constants.h"
#include "tlv_apdu.h"
#include "gtp_field.h"
#include "cmd_tx_info.h"
#include "gtp_tx_info.h"
#include "tx_ctx.h"
#include "gcs_limits.h"
#include "gcs_signing_context.h"
#include "gcs_memory.h"

static bool handle_tlv_payload(const buffer_t *buf) {
    s_field field = {0};
    s_field_ctx ctx = {0};

    if ((appState == APP_STATE_SIGNING_TX) &&
        !gcs_account_descriptor(buf->size, true)) {
        return false;
    }
    ctx.field = &field;
    if (!handle_field_struct(buf, &ctx)) {
        PRINTF("Error: could not handle the field struct!\n");
        cleanup_field_constraints(&field);
        return false;
    }
    if (cx_hash_no_throw(get_fields_hash_ctx(), 0, buf->ptr, buf->size, NULL, 0) != CX_OK) {
        PRINTF("Error: could not hash the field struct!\n");
        cleanup_field_constraints(&field);
        return false;
    }
    if (!verify_field_struct(&ctx)) {
        PRINTF("Error: could not verify the field struct!\n");
        cleanup_field_constraints(&field);
        return false;
    }
    if (!format_field(&field)) {
        return false;
    }
    while (((appState == APP_STATE_SIGNING_EIP712) || !tx_ctx_is_root()) &&
           validate_instruction_hash()) {
        if (!process_empty_txs_after()) {
            return false;
        }
        tx_ctx_pop();
    }
    return true;
}

uint16_t handle_field(uint8_t p1, uint8_t p2, uint8_t lc, const uint8_t *payload) {
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

    if (get_current_tx_info() == NULL) {
        PRINTF("Error: Field received without a TX info!\n");
        tlv_apdu_reset();
        gcs_cleanup();
        return SWO_COMMAND_NOT_ALLOWED;
    }

    if (!tlv_from_apdu(INS_GTP_FIELD,
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
