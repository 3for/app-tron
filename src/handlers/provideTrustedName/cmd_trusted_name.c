#include <stdbool.h>
#include "cmd_trusted_name.h"
#include "trusted_name.h"
#include "challenge.h"
#include "tlv_apdu.h"
#include "app_errors.h"
#include "handlers.h"
#include "io.h"

static bool handle_tlv_payload(const uint8_t *payload, uint16_t size) {
    s_trusted_name_ctx ctx = {0};
    bool ret;

    cx_sha256_init(&ctx.hash_ctx);
    if (!tlv_parse(payload, size, (f_tlv_data_handler) &handle_trusted_name_struct, &ctx)) {
        ret = false;
    } else {
        ret = verify_trusted_name_struct(&ctx);
    }
    roll_challenge();  // prevent brute-force guesses and replays
    return ret;
}

/**
 * Handle trusted name APDU
 *
 * @param[in] p1 first APDU instruction parameter
 * @param[in] data APDU payload
 * @param[in] length payload size
 */
uint16_t handle_trusted_name(uint8_t p1, uint8_t p2, const uint8_t *data, uint8_t length) {
    UNUSED(p2);
    if (!tlv_from_apdu(p1 == P1_FIRST_CHUNK, length, data, &handle_tlv_payload)) {
        return io_send_sw(E_INCORRECT_DATA);
    }
    return io_send_sw(E_OK);
}
