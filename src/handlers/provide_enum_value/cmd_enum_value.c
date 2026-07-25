#include "cmd_enum_value.h"
#include "apdu_constants.h"
#include "enum_value.h"
#include "tlv_apdu.h"

static uint16_t g_enum_value_status;

static bool handle_tlv_payload(const buffer_t *buf) {
    bool ret = false;
    s_enum_value_ctx ctx = {0};

    cx_sha256_init(&ctx.hash_ctx);
    ret = handle_enum_value_tlv_payload(buf, &ctx);
    if (!ret) return false;
    g_enum_value_status = verify_enum_value_struct(&ctx);
    return g_enum_value_status == SWO_SUCCESS;
}

uint16_t handle_enum_value(uint8_t p1, uint8_t p2, uint8_t lc, const uint8_t *payload) {
    if ((p2 != 0x00) ||
        ((p1 != P1_FIRST_CHUNK) && (p1 != P1_FOLLOWING_CHUNK))) {
        tlv_apdu_reset();
        return SWO_WRONG_P1_P2;
    }
    g_enum_value_status = SWO_INCORRECT_DATA;
    if (!tlv_from_apdu(INS_PROVIDE_ENUM_VALUE,
                       p2,
                       p1 == P1_FIRST_CHUNK,
                       lc,
                       payload,
                       ENUM_VALUE_DESCRIPTOR_MAX_LENGTH,
                       &handle_tlv_payload)) {
        return g_enum_value_status;
    }
    return SWO_SUCCESS;
}
