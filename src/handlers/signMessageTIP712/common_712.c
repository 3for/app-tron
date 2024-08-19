// #include "shared_context.h"
// #include "apdu_constants.h"
#include "os_io_seproxyhal.h"
#include "crypto_helpers.h"
// #include "ui_callbacks.h"
#include "common_712.h"
// #include "ui_callbacks.h"
#include "ui_idle_menu.h"
#include "parse.h"
#include "ui_globals.h"
#include "app_errors.h"
#include "helpers.h"

extern void reset_app_context();

static const uint8_t TIP_MAGIC[] = {0x19, 0x01};

unsigned int ui_712_approve_cb(void) {
    uint8_t hash[INT256_LENGTH];
    uint32_t tx = 0;

    io_seproxyhal_io_heartbeat();
    CX_ASSERT(cx_keccak_init_no_throw(&global_sha3, 256));
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &global_sha3,
                               0,
                               (uint8_t *) TIP_MAGIC,
                               sizeof(TIP_MAGIC),
                               NULL,
                               0));
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &global_sha3,
                               0,
                               global_ctx.messageSigningContext712.domainHash,
                               sizeof(global_ctx.messageSigningContext712.domainHash),
                               NULL,
                               0));
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &global_sha3,
                               CX_LAST,
                               global_ctx.messageSigningContext712.messageHash,
                               sizeof(global_ctx.messageSigningContext712.messageHash),
                               hash,
                               sizeof(hash)));
    PRINTF("New TIP712 Domain hash 0x%.*h\n", 32, global_ctx.messageSigningContext712.domainHash);
    PRINTF("New TIP712 Message hash 0x%.*h\n", 32, global_ctx.messageSigningContext712.messageHash);
    PRINTF("New TIP712 hash to sign %.*H\n", 32, hash);
    PRINTF("New TIP712 bip32 %.*H\n", 40, (uint8_t*) (&global_ctx.messageSigningContext712.bip32Path[0]));
    unsigned int info = 0;
    if (bip32_derive_ecdsa_sign_rs_hash_256(CX_CURVE_256K1,
                                            global_ctx.messageSigningContext712.bip32Path,
                                            global_ctx.messageSigningContext712.pathLength,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            hash,
                                            sizeof(hash),
                                            G_io_apdu_buffer + 1,
                                            G_io_apdu_buffer + 1 + 32,
                                            &info) != CX_OK) {
        THROW(APDU_RESPONSE_UNKNOWN);
    }
    G_io_apdu_buffer[0] = 27;
    if (info & CX_ECCINFO_PARITY_ODD) {
        G_io_apdu_buffer[0]++;
    }
    if (info & CX_ECCINFO_xGTn) {
        G_io_apdu_buffer[0] += 2;
    }
    tx = 65;
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    PRINTF("TIP712 SIGN 0x%.*h\n", 64, G_io_apdu_buffer);
    reset_app_context();
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0;  // do not redraw the widget
}

unsigned int ui_712_reject_cb(void) {
    reset_app_context();
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0;  // do not redraw the widget
}
