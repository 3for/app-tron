#include <stdbool.h>
#include "cmd_trusted_name.h"
#include "trusted_name.h"
#include "challenge.h"
#include "tlv_apdu.h"
#include "apdu_constants.h"
#include "ui_utils.h"
#include "gcs_memory.h"

static uint16_t g_trusted_name_status;

static bool handle_tlv_payload_with_status(const buffer_t *buf) {
    s_trusted_name_ctx ctx = {0};

    cx_sha256_init(&ctx.hash_ctx);
    if (!handle_trusted_name_tlv_payload(buf, &ctx)) {
        g_trusted_name_status = SWO_INCORRECT_DATA;
        return false;
    }
    g_trusted_name_status = verify_trusted_name_struct(&ctx);
    if (ctx.challenge_received) {
        roll_challenge();
    }
    return g_trusted_name_status == SWO_SUCCESS;
}

/**
 * Handle trusted name APDU
 *
 * @param[in] p1 first APDU instruction parameter
 * @param[in] data APDU payload
 * @param[in] length payload size
 */
uint16_t handle_trusted_name(uint8_t p1, uint8_t p2, const uint8_t *data, uint8_t length) {
    if ((p2 != 0) || ((p1 != P1_FIRST_CHUNK) && (p1 != P1_FOLLOWING_CHUNK))) {
        tlv_apdu_reset();
        return SWO_WRONG_P1_P2;
    }
    g_trusted_name_status = SWO_INCORRECT_DATA;
    if (!tlv_from_apdu(INS_PROVIDE_TRUSTED_NAME,
                       p2,
                       p1 == P1_FIRST_CHUNK,
                       length,
                       data,
                       TRUSTED_NAME_DESCRIPTOR_MAX_LENGTH,
                       &handle_tlv_payload_with_status)) {
        return gcs_mem_take_allocation_failure() ? SWO_INSUFFICIENT_MEMORY
                                                 : g_trusted_name_status;
    }
    return SWO_SUCCESS;
}
