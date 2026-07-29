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

#include "apdu_constants.h"
#include "helpers.h"
#include "ui_review_menu.h"
#include "ui_globals.h"
#include "app_errors.h"

#ifdef HAVE_SWAP
#include "swap.h"
#include "handle_swap_sign_transaction.h"
#endif  // HAVE_SWAP

static int send_public_key_status(uint16_t sw) {
#ifdef HAVE_SWAP
    if ((sw != E_OK) && G_called_from_swap) {
        io_send_sw(sw);
        swap_finalize_exchange_sign_transaction(false);
    }
#endif  // HAVE_SWAP
    return io_send_sw(sw);
}

int handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength) {
    // Get private key data
    bip32_path_t bip32_path;

    if ((p1 != P1_CONFIRM) && (p1 != P1_NON_CONFIRM)) {
        return send_public_key_status(E_INCORRECT_P1_P2);
    }
    if ((p2 != P2_CHAINCODE) && (p2 != P2_NO_CHAINCODE)) {
        return send_public_key_status(E_INCORRECT_P1_P2);
    }

    tmpCtx.publicKeyContext.getChaincode = (p2 == P2_CHAINCODE);

    // Add requested BIP path to tmp array
    off_t parsed = read_bip32_path(dataBuffer, dataLength, &bip32_path);
    if ((parsed < 0) || ((size_t) parsed != dataLength)) {
        PRINTF("read_bip32_path failed\n");
        return send_public_key_status(E_INCORRECT_BIP32_PATH);
    }

    if (initPublicKeyContext(&bip32_path,
                             tmpCtx.publicKeyContext.address58,
                             &tmpCtx.publicKeyContext) != 0) {
        return send_public_key_status(E_SECURITY_STATUS_NOT_SATISFIED);
    }

    memcpy(strings.common.toAddress, tmpCtx.publicKeyContext.address58, BASE58CHECK_ADDRESS_SIZE + 1);

    if (p1 == P1_NON_CONFIRM) {
        return helper_send_response_pubkey(&tmpCtx.publicKeyContext);
    } else {
#ifdef HAVE_SWAP
        if (G_called_from_swap) {
            PRINTF("Refused GET_PUBLIC_KEY mode when in SWAP mode\n");
            return send_public_key_status(E_SWAP_CHECKING_FAIL);
        }
#endif  // HAVE_SWAP

        // The address review is asynchronous. Mark ownership before starting
        // NBGL so the dispatcher cannot run another command that replies to a
        // different APDU or replaces tmpCtx while this page is active.
        appState = APP_STATE_REVIEWING_ADDRESS;
        if (!ux_flow_display(APPROVAL_VERIFY_ADDRESS, false)) {
            reset_app_context();
            return send_public_key_status(SWO_INSUFFICIENT_MEMORY);
        }
        return 0;
    }
}
