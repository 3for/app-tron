#ifdef HAVE_TRUSTED_NAME

#include <stdbool.h>
#include "cmd_trusted_name.h"
#include "trusted_name.h"
#include "mem.h"
#include "challenge.h"
#include "tlv_apdu.h"
//#include "apdu_constants.h"
#include "app_errors.h"
#include "handlers.h"

//TODO. refactor later
extern void handle_return_code(uint16_t apdu_response_code);

static bool handle_tlv_payload(const uint8_t *payload, uint16_t size, bool to_free) {
    s_trusted_name_ctx ctx = {0};
    bool parsing_ret;

    ctx.trusted_name.name = g_trusted_name;
    cx_sha256_init(&ctx.hash_ctx);
    parsing_ret = tlv_parse(payload, size, (f_tlv_data_handler) &handle_trusted_name_struct, &ctx);
    if (to_free) mem_dealloc(size);
    if (!parsing_ret || !verify_trusted_name_struct(&ctx)) {
        roll_challenge();  // prevent brute-force guesses
        return false;
    }
    roll_challenge();  // prevent replays
    return true;
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
        //TODO. refactor later
        //return APDU_RESPONSE_INVALID_DATA;
        handle_return_code(APDU_RESPONSE_INVALID_DATA);
        return 0;
    }
    handle_return_code(APDU_RESPONSE_OK);
    //TODO. refactor later
    return APDU_RESPONSE_OK;
}

#endif  // HAVE_TRUSTED_NAME
