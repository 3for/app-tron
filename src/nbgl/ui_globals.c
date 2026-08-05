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

// The transaction display strings (fromAddress, toAddress, addressSummary,
// fullContract, url, TRC20Action, TRC20ActionSendAllow, fullHash) now live in
// txStringProperties_t and are accessed via `strings.common.*`, mirroring
// app-ethereum's shared_context.h layout.
volatile uint8_t customContractField;
uint8_t votes_count;
char *vote_display_buffer;
cx_sha3_t global_sha3;
strings_t strings;

uint8_t perm_field_count;
const char *perm_field_items[PERM_MAX_FIELDS];
char (*perm_field_labels)[PERM_ITEM_LEN];
char (*perm_field_values)[PERM_VAL_LEN];

extern void reset_app_context();

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
        io_send_sw(E_INTERNAL_ERROR);
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
#ifdef HAVE_SWAP
    if (G_called_from_swap && G_swap_response_ready) {
        io_send_sw(E_USER_REJECTED);
        swap_finalize_exchange_sign_transaction(false);
    }
#endif  // HAVE_SWAP

    reset_app_context();
    io_send_sw(E_USER_REJECTED);

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
        io_send_sw(E_INTERNAL_ERROR);
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
    return io_seproxyhal_send_status(E_USER_REJECTED, 0, true, false);
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
        io_send_sw(E_INTERNAL_ERROR);
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
