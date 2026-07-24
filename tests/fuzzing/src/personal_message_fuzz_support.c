#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "apdu_constants.h"
#include "cx.h"
#include "helpers.h"
#include "io.h"
#include "parse.h"
#include "ui_globals.h"
#include "ui_review_menu.h"

tmpCtx_t tmpCtx;
txContent_t txContent;
txContext_t txContext;
uint8_t appState;
uint16_t apdu_response_code;
cx_sha3_t global_sha3;
strings_t strings;

static bool g_fail_public_key_init;
static volatile uint32_t g_display_checksum;
static const char *g_review_message;

void reset_app_context(void) {
    message_cleanup();
    personal_message_legacy_cleanup();
    memset(&tmpCtx, 0, sizeof(tmpCtx));
    memset(&txContent, 0, sizeof(txContent));
    memset(&txContext, 0, sizeof(txContext));
    memset(&global_sha3, 0, sizeof(global_sha3));
    memset(&strings, 0, sizeof(strings));
    apdu_response_code = 0x9000U;
    appState = APP_STATE_IDLE;
}

void fuzz_personal_message_init(uint8_t control) {
    reset_app_context();
    g_fail_public_key_init = (control & 1U) != 0U;
    g_display_checksum = 0U;
}

int io_send_sw(uint16_t sw) {
    apdu_response_code = sw;
    return sw;
}

int initPublicKeyContext(bip32_path_t *bip32_path,
                         char *address58,
                         publicKeyContext_t *public_key_ctx) {
    if (g_fail_public_key_init) {
        return -1;
    }

    memset(public_key_ctx, 0, sizeof(*public_key_ctx));
    public_key_ctx->publicKey[0] = 0x04U;
    for (size_t i = 1U; i < sizeof(public_key_ctx->publicKey); i++) {
        uint32_t component = 0U;
        if ((bip32_path != NULL) && (bip32_path->length != 0U)) {
            component = bip32_path->indices[(i - 1U) % bip32_path->length];
        }
        public_key_ctx->publicKey[i] =
            (uint8_t) (component >> (((i - 1U) & 3U) * 8U));
    }

    uint8_t address[ADDRESS_SIZE];
    getAddressFromPublicKey(public_key_ctx->publicKey, address);
    getBase58FromAddress(address, address58);
    return 0;
}

bool ux_flow_display(ui_approval_state_t state, bool warning) {
    (void) state;
    (void) warning;
    return true;
}

void ui_191_start(const char *message) {
    uint32_t checksum = 0U;

    if (message == NULL) {
        __builtin_trap();
    }
    for (size_t i = 0U; message[i] != '\0'; i++) {
        checksum = (checksum * 33U) ^ (uint8_t) message[i];
    }
    g_display_checksum = checksum;
    g_review_message = message;
}

void ui_191_cleanup(void) {
    g_review_message = NULL;
}
