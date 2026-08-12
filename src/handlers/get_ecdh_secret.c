/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2023 Ledger
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
#include <stdint.h>

#include "io.h"

#include "helpers.h"
#include "ui_review_menu.h"
#include "app_errors.h"
#include "ui_globals.h"

typedef enum {
    ECDH_PUBLIC_KEY_VALID = 0,
    ECDH_PUBLIC_KEY_INVALID,
    ECDH_PUBLIC_KEY_INTERNAL_ERROR,
} ecdh_public_key_validation_t;

static ecdh_public_key_validation_t validate_ecdh_public_key(
    const uint8_t public_key[static PUBLIC_KEY_SIZE]) {
    cx_ecpoint_t point;
    cx_err_t error;
    size_t coordinate_size;
    bool is_on_curve = false;
    bool is_at_infinity = false;
    ecdh_public_key_validation_t result = ECDH_PUBLIC_KEY_INTERNAL_ERROR;

    // Only the canonical SEC1 uncompressed representation is accepted. Both
    // getAddressFromPublicKey() and cx_ecdh_no_throw() consume X/Y starting at
    // byte one, so accepting another prefix would otherwise make that byte
    // invisible to both the review address and the derived secret.
    if (public_key[0] != 0x04U) {
        return ECDH_PUBLIC_KEY_INVALID;
    }

    error = cx_ecdomain_parameters_length(CX_CURVE_256K1, &coordinate_size);
    if ((error != CX_OK) ||
        (coordinate_size != ((PUBLIC_KEY_SIZE - 1U) / 2U))) {
        return ECDH_PUBLIC_KEY_INTERNAL_ERROR;
    }

    error = cx_bn_lock(coordinate_size, 0);
    if (error != CX_OK) {
        return ECDH_PUBLIC_KEY_INTERNAL_ERROR;
    }

    error = cx_ecpoint_alloc(&point, CX_CURVE_256K1);
    if (error != CX_OK) {
        goto end;
    }
    error = cx_ecpoint_init(&point,
                            public_key + 1U,
                            coordinate_size,
                            public_key + 1U + coordinate_size,
                            coordinate_size);
    if (error != CX_OK) {
        // Coordinates outside the field are malformed peer input. Errors that
        // cannot be caused by the supplied coordinates remain internal errors.
        if (error == CX_INVALID_PARAMETER) {
            result = ECDH_PUBLIC_KEY_INVALID;
        }
        goto end;
    }

    error = cx_ecpoint_is_on_curve(&point, &is_on_curve);
    if (error == CX_EC_INFINITE_POINT) {
        result = ECDH_PUBLIC_KEY_INVALID;
        goto end;
    }
    if (error != CX_OK) {
        goto end;
    }
    if (!is_on_curve) {
        result = ECDH_PUBLIC_KEY_INVALID;
        goto end;
    }

    error = cx_ecpoint_is_at_infinity(&point, &is_at_infinity);
    if (error != CX_OK) {
        goto end;
    }
    result = is_at_infinity ? ECDH_PUBLIC_KEY_INVALID : ECDH_PUBLIC_KEY_VALID;

end:
    cx_bn_unlock();
    return result;
}

int handleECDHSecret(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    if ((p1 != 0x00) || (p2 != 0x01)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    off_t ret = read_bip32_path(workBuffer, dataLength, &tmpCtx.transactionContext.bip32_path);
    if (ret < 0) {
        return io_send_sw(E_INCORRECT_BIP32_PATH);
    }
    workBuffer += ret;
    dataLength -= ret;
    if (dataLength != PUBLIC_KEY_SIZE) {
        PRINTF("Public key length error!");
        return io_send_sw(E_INCORRECT_LENGTH);
    }

    switch (validate_ecdh_public_key(workBuffer)) {
        case ECDH_PUBLIC_KEY_VALID:
            break;
        case ECDH_PUBLIC_KEY_INVALID:
            return io_send_sw(E_INCORRECT_DATA);
        case ECDH_PUBLIC_KEY_INTERNAL_ERROR:
        default:
            return io_send_sw(E_INTERNAL_ERROR);
    }

    publicKeyContext_t tmp_public_key_ctx;
    if (initPublicKeyContext(&tmpCtx.transactionContext.bip32_path,
                             strings.common.fromAddress,
                             &tmp_public_key_ctx) != 0) {
        return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }

    // Load raw Data
    memcpy(tmpCtx.transactionContext.signature, workBuffer, PUBLIC_KEY_SIZE);

    // Get base58 address from workBuffer public key
    getBase58FromPublicKey(tmpCtx.transactionContext.signature, strings.common.toAddress);

    // The NBGL review is asynchronous and continues to own the BIP32 path and
    // peer public key in tmpCtx. It must begin from idle so the dispatcher
    // rejects every interleaved APDU while the page is active. On preparation
    // failure ux_flow_display completes the pending APDU and resets the context.
    LEDGER_ASSERT(appState == APP_STATE_IDLE, "idle required");
    appState = APP_STATE_REVIEWING_OPERATION;
    if (!ux_flow_display(APPROVAL_SHARED_ECDH_SECRET, false)) {
        return 0;
    }

    return 0;
}
