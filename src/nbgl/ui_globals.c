/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2022 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
#include "ui_globals.h"
#include "helpers.h"
#include "io.h"
#include "os.h"
#include "ux.h"
#include "crypto_helpers.h"
#include "ui_idle_menu.h"
#include "app_errors.h"
#include "nbgl_use_case.h"
#include "ui_logic.h"
#include "ui_callbacks.h"

#ifdef HAVE_SWAP
#include "swap.h"
#include "../swap/handle_swap_sign_transaction.h"
#endif  // HAVE_SWAP

volatile uint8_t customContractField;
char fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];  // 5 extra bytes used to inform MultSign ID
char toAddress[BASE58CHECK_ADDRESS_SIZE + 1];
char addressSummary[40];
char fullContract[MAX_TOKEN_LENGTH];
char url[MAX_URL_SIZE];
char TRC20Action[9];
char TRC20ActionSendAllow[8];
char fullHash[HASH_SIZE * 2 + 1];
int8_t votes_count;
cx_sha3_t global_sha3;
strings_t strings;

extern void reset_app_context();

/**
 * Reset the UI buffer
 *
 * Simply sets its first byte to a NULL character
 */
void reset_ui_191_buffer(void) {
    UI_191_BUFFER[0] = '\0';
}

/**
 * Get used space from UI buffer
 *
 * @return size in bytes
 */
size_t ui_191_buffer_length(void) {
    return strlen(UI_191_BUFFER);
}

/**
 * Get remaining space from UI buffer
 *
 * @return size in bytes
 */
size_t remaining_ui_191_buffer_length(void) {
    // -1 for the ending NULL byte
    return (sizeof(UI_191_BUFFER) - 1) - ui_191_buffer_length();
}

/**
 * Get free space from UI buffer
 *
 * @return pointer to the free space
 */
char *remaining_ui_191_buffer(void) {
    return &UI_191_BUFFER[ui_191_buffer_length()];
}

bool ui_callback_address_ok(bool display_menu) {
    helper_send_response_pubkey(&tmpCtx.publicKeyContext);

    reset_app_context();
    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return true;
}

bool ui_callback_signMessage_ok(bool display_menu) {
    bool ret = true;

    if (signTransaction(&tmpCtx.transactionContext) != 0) {
        io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
        ret = false;
    } else {
        io_send_response_pointer(tmpCtx.transactionContext.signature,
                                 tmpCtx.transactionContext.signatureLength,
                                 E_OK);
    }

    reset_app_context();
    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return ret;
}

bool ui_callback_tx_cancel(bool display_menu) {
    reset_app_context();
    io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);

    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return true;
}

bool ui_callback_tx_ok(bool display_menu) {
    bool ret = true;
#ifdef HAVE_SWAP
    bool quit_swap = G_called_from_swap && G_swap_response_ready;
#endif  // HAVE_SWAP

    if (signTransaction(&tmpCtx.transactionContext) != 0) {
        io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
        ret = false;
    } else {
        io_send_response_pointer(tmpCtx.transactionContext.signature,
                                 tmpCtx.transactionContext.signatureLength,
                                 E_OK);
    }

#ifdef HAVE_SWAP
    if (quit_swap) {
        swap_finalize_exchange_sign_transaction(ret);
    }
#endif  // HAVE_SWAP

    reset_app_context();
    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return ret;
}

// app-ethereum parity wrappers: the GCS review screen (src/nbgl/ui_gcs.c) drives
// signing through these io_seproxyhal_touch_tx_ok/cancel entry points, exactly
// like app-ethereum. They sign/reject without redisplaying the idle UX, because
// review_choice() chains nbgl_useCaseReviewStatus(..., ui_idle) for that.
unsigned int io_seproxyhal_touch_tx_ok(void) {
    ui_callback_tx_ok(false);
    return 0;
}

unsigned int io_seproxyhal_touch_tx_cancel(void) {
    ui_callback_tx_cancel(false);
    return 0;
}

bool ui_callback_ecdh_ok(bool display_menu) {
    cx_err_t err;
    cx_ecfp_private_key_t privateKey;
    uint32_t tx = 0;

    // Get private key
    err = bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                        tmpCtx.transactionContext.bip32_path.indices,
                                        tmpCtx.transactionContext.bip32_path.length,
                                        &privateKey,
                                        NULL);
    if (err != CX_OK) {
        goto end;
    }

    err = cx_ecdh_no_throw(&privateKey,
                           CX_ECDH_POINT,
                           tmpCtx.transactionContext.signature,
                           65,
                           G_io_apdu_buffer,
                           sizeof(G_io_apdu_buffer));
    if (err != CX_OK) {
        goto end;
    }

    size_t size;
    err = cx_ecdomain_parameters_length(CX_CURVE_256K1, &size);
    tx = 1 + 2 * size;

end:
    // Clear tmp buffer data
    explicit_bzero(&privateKey, sizeof(privateKey));

    reset_app_context();
    if (err == CX_OK) {
        io_send_response_pointer(G_io_apdu_buffer, tx, E_OK);
    } else {
        io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    if (err == CX_OK) {
        return true;
    } else {
        return false;
    }
}
