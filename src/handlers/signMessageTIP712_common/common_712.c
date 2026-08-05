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

#include <string.h>

#include "common_712.h"
#include "ui_globals.h"     // strings, parse.h, shared_context.h (tmpCtx/appState/reset_app_context)
#include "helpers.h"
#include "io.h"
#include "os.h"
#include "ux.h"
#include "crypto_helpers.h"
#include "ui_idle_menu.h"   // ui_idle
#include "app_errors.h"     // E_OK, SWO_* status words
#include "nbgl_use_case.h"  // BLIND_SIGNING_WARN
#include "ui_logic.h"       // e_tip712_filtering_mode, ui_sign_712
#include "ui_nbgl.h"        // warning
#include "utils.h"          // SET_BIT
#include "context_712.h"

// TIP-712 (EIP-191 0x19 / version 0x01) signing prefix.
static const uint8_t TIP_712_MAGIC[] = {0x19, 0x01};

#define TIP712_ECDSA_COMPONENT_LENGTH 32U
#define TIP712_SIGNATURE_RS_LENGTH    (2U * TIP712_ECDSA_COMPONENT_LENGTH)
#define TIP712_SIGNATURE_LENGTH       (TIP712_SIGNATURE_RS_LENGTH + 1U)

bool tip712_hash_to_sign(uint8_t hash[static INT256_LENGTH]) {
    cx_sha3_t sha3;
    if (cx_keccak_init_no_throw(&sha3, 256) != CX_OK) {
        return false;
    }
    if (cx_hash_no_throw((cx_hash_t *) &sha3,
                         0,
                         (uint8_t *) TIP_712_MAGIC,
                         sizeof(TIP_712_MAGIC),
                         NULL,
                         0) != CX_OK) {
        return false;
    }

    if (cx_hash_no_throw((cx_hash_t *) &sha3,
                         0,
                         tmpCtx.messageSigningContext712.domainHash,
                         sizeof(tmpCtx.messageSigningContext712.domainHash),
                         NULL,
                         0) != CX_OK) {
        return false;
    }

    if (cx_hash_no_throw((cx_hash_t *) &sha3,
                         CX_LAST,
                         tmpCtx.messageSigningContext712.messageHash,
                         sizeof(tmpCtx.messageSigningContext712.messageHash),
                         hash,
                         INT256_LENGTH) != CX_OK) {
        return false;
    }

    PRINTF("TIP712 Domain hash 0x%.*H\n", 32, tmpCtx.messageSigningContext712.domainHash);
    PRINTF("TIP712 Message hash 0x%.*H\n", 32, tmpCtx.messageSigningContext712.messageHash);
    PRINTF("TIP712 hash to sign 0x%.*H\n", 32, hash);

    return true;
}

bool ui_712_approve_cb(bool display_menu) {
    uint32_t tx = 0;
    cx_err_t err = CX_INTERNAL_ERROR;

    uint32_t info = 0;
    uint8_t hash[INT256_LENGTH] = {0};

    io_seproxyhal_io_heartbeat();
    if (!tip712_hash_to_sign(hash)) {
        goto end;
    }

    io_seproxyhal_io_heartbeat();
    err = bip32_derive_ecdsa_sign_rs_hash_256(CX_CURVE_256K1,
                                              tmpCtx.messageSigningContext712.bip32Path,
                                              tmpCtx.messageSigningContext712.pathLength,
                                              CX_RND_RFC6979 | CX_LAST,
                                              CX_SHA256,
                                              hash,
                                              sizeof(hash),
                                              G_io_apdu_buffer,
                                              G_io_apdu_buffer + TIP712_ECDSA_COMPONENT_LENGTH,
                                              &info);
    if (err != CX_OK) {
        goto end;
    }

    G_io_apdu_buffer[TIP712_SIGNATURE_RS_LENGTH] = 0;
    if (info & CX_ECCINFO_PARITY_ODD) {
        G_io_apdu_buffer[TIP712_SIGNATURE_RS_LENGTH]++;
    }
    tx = TIP712_SIGNATURE_LENGTH;
end:
    // The SDK signing helper clears its temporary private key on every path.
    explicit_bzero(hash, sizeof(hash));
    if (err != CX_OK) {
        // Do not leave a partial r/s output available to later code.
        explicit_bzero(G_io_apdu_buffer, TIP712_SIGNATURE_LENGTH);
    }

    reset_app_context();
    if (err == CX_OK) {
        // Send back the response, do not restart the event loop
        io_send_response_pointer(G_io_apdu_buffer, tx, E_OK);
    } else {
        // A cryptographic helper failure is an internal/unclassified error, not
        // an unmet device security state such as a locked device or invalid
        // access rights.
        io_send_sw(SWO_PARAMETER_ERROR_NO_INFO);
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

bool ui_712_reject_cb(bool display_menu) {
    reset_app_context();
    // Send back the response, do not restart the event loop
    io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return true;
}

static char *format_hash(const uint8_t *hash, char *buffer, size_t buffer_size, size_t offset) {
    bytes_to_string(buffer + offset, buffer_size - offset, hash, 32);
    return buffer + offset;
}

void tip712_format_hash(uint8_t index, const char **item, const char **value) {
    if ((item == NULL) || (value == NULL)) {
        return;
    }
    switch (index) {
        case 0:
            *item = "Domain hash";
            *value = format_hash(tmpCtx.messageSigningContext712.domainHash,
                                 strings.tmp.tmp,
                                 sizeof(strings.tmp.tmp),
                                 0);
            break;
        case 1:
            *item = "Message hash";
            *value = format_hash(tmpCtx.messageSigningContext712.messageHash,
                                 strings.tmp.tmp,
                                 sizeof(strings.tmp.tmp),
                                 70);
            break;
        default:
            *item = NULL;
            *value = NULL;
            break;
    }
}

/**
 * Initialize the TIP712 flow
 *
 * @param filtering the filtering mode to use for the TIP712 flow
 * @return status code indicating success or failure
 */
uint16_t ui_712_start(e_tip712_filtering_mode filtering) {
    /* This is called from inside the full TIP-712 parser. Resetting here would
     * free that parser's own context and let its caller continue on stale
     * pointers. Conflicts are rejected and cleaned by the outer handler. */
    if (!tip712_full_session_in_progress() ||
        ((appState != APP_STATE_IDLE) &&
         (appState != APP_STATE_SIGNING_TIP712))) {
        return SWO_CONDITIONS_NOT_SATISFIED;
    }
    appState = APP_STATE_SIGNING_TIP712;
    explicit_bzero(&strings, sizeof(strings));
    explicit_bzero(&warning, sizeof(nbgl_warning_t));
    if (filtering == TIP712_FILTERING_BASIC) {
        // Not fully filtered: surface the blind-signing warning.
        warning.predefinedSet |= SET_BIT(BLIND_SIGNING_WARN);
#ifdef HAVE_GATING_SUPPORT
        warning.predefinedSet |= SET_BIT(GATED_SIGNING_WARN);
#endif  // HAVE_GATING_SUPPORT
    }
    return SWO_SUCCESS;
}
