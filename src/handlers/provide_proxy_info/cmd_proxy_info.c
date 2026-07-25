#include "cmd_proxy_info.h"
#include "proxy_info.h"
#include "tlv_apdu.h"
#include "apdu_constants.h"

static bool handle_tlv_payload(const buffer_t *buf) {
    s_proxy_info_ctx ctx = {0};
    bool parsing_ret = false;

    cx_sha256_init(&ctx.struct_hash);
    parsing_ret = handle_proxy_info_tlv_payload(buf, &ctx);
    if (!parsing_ret || !verify_proxy_info_struct(&ctx)) {
        return false;
    }
    return true;
}

uint16_t handle_proxy_info(uint8_t p1, uint8_t p2, uint8_t lc, const uint8_t *payload) {
    if ((p2 != 0x00) ||
        ((p1 != P1_FIRST_CHUNK) && (p1 != P1_FOLLOWING_CHUNK))) {
        tlv_apdu_reset();
        return SWO_WRONG_P1_P2;
    }
    if (!tlv_from_apdu(INS_PROVIDE_PROXY_INFO,
                       p2,
                       p1 == P1_FIRST_CHUNK,
                       lc,
                       payload,
                       PROXY_INFO_DESCRIPTOR_MAX_LENGTH,
                       &handle_tlv_payload)) {
        return SWO_INCORRECT_DATA;
    }
    return SWO_SUCCESS;
}
