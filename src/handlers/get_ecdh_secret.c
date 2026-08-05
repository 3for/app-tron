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

int handleECDHSecret(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    if ((p1 != 0x00) || (p2 != 0x01)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    off_t ret = read_bip32_path(workBuffer, dataLength, &tmpCtx.transactionContext.bip32_path);
    if (ret < 0) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }
    workBuffer += ret;
    dataLength -= ret;
    if (dataLength != PUBLIC_KEY_SIZE) {
        PRINTF("Public key length error!");
        return io_send_sw(SWO_WRONG_DATA_LENGTH);
    }

    publicKeyContext_t tmp_public_key_ctx;
    if (initPublicKeyContext(&tmpCtx.transactionContext.bip32_path,
                             strings.common.fromAddress,
                             &tmp_public_key_ctx) != 0) {
        return io_send_sw(SWO_UNKNOWN);
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
