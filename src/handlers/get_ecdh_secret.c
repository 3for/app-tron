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

#include "cx.h"
#include "io.h"

#include "helpers.h"
#include "ui_review_menu.h"
#include "app_errors.h"
#include "ui_globals.h"

#define SECP256K1_COORDINATE_SIZE ((PUBLIC_KEY_SIZE - 1) / 2)

static bool isValidECDHPeerPublicKey(const uint8_t publicKey[static PUBLIC_KEY_SIZE]) {
    cx_err_t err;
    cx_ecpoint_t point;
    bool pointAllocated = false;
    bool isOnCurve = false;
    bool isAtInfinity = false;

    // Preserve the uncompressed format used by existing clients, but reject
    // non-canonical encodings before deriving or displaying any key material.
    if (publicKey[0] != 0x04) {
        return false;
    }

    err = cx_bn_lock(SECP256K1_COORDINATE_SIZE, 0);
    if (err != CX_OK) {
        return false;
    }

    err = cx_ecpoint_alloc(&point, CX_CURVE_256K1);
    if (err == CX_OK) {
        pointAllocated = true;
        err = cx_ecpoint_init(&point,
                              publicKey + 1,
                              SECP256K1_COORDINATE_SIZE,
                              publicKey + 1 + SECP256K1_COORDINATE_SIZE,
                              SECP256K1_COORDINATE_SIZE);
    }
    if (err == CX_OK) {
        err = cx_ecpoint_is_on_curve(&point, &isOnCurve);
    }
    if ((err == CX_OK) && isOnCurve) {
        err = cx_ecpoint_is_at_infinity(&point, &isAtInfinity);
    }

    if (pointAllocated) {
        cx_err_t destroyErr = cx_ecpoint_destroy(&point);
        if (err == CX_OK) {
            err = destroyErr;
        }
    }
    (void) cx_bn_unlock();

    return (err == CX_OK) && isOnCurve && !isAtInfinity;
}

int handleECDHSecret(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    if ((p1 != 0x00) || (p2 != 0x01)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    off_t ret = read_bip32_path(workBuffer, dataLength, &transactionContext.bip32_path);
    if (ret < 0) {
        return io_send_sw(E_INCORRECT_BIP32_PATH);
    }
    workBuffer += ret;
    dataLength -= ret;
    if (dataLength != PUBLIC_KEY_SIZE) {
        PRINTF("Public key length error!");
        return io_send_sw(E_INCORRECT_LENGTH);
    }
    if (initPublicKeyContext(&transactionContext.bip32_path, fromAddress) != 0) {
        return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }
    if (!isValidECDHPeerPublicKey(workBuffer)) {
        PRINTF("Invalid ECDH public key!\n");
        return io_send_sw(E_INCORRECT_DATA);
    }

    // Load raw Data
    memcpy(transactionContext.signature, workBuffer, PUBLIC_KEY_SIZE);

    // Get base58 address from workBuffer public key
    getBase58FromPublicKey(transactionContext.signature, toAddress);

    ux_flow_display(APPROVAL_SHARED_ECDH_SECRET, false);

    return 0;
}
