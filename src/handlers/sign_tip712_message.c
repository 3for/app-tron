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

#include "format.h"

#include "helpers.h"
#include "ui_review_menu.h"
#include "app_errors.h"
#include "apdu_constants.h"
#include "parse.h"
#include "ui_globals.h"
#include "settings.h"
#include "context_712.h"

extern void reset_app_context();

uint16_t handleSignTIP712Message(uint8_t p1, const uint8_t *workBuffer, uint8_t dataLength) {
    uint8_t i;

    if (!N_storage.signByHash) {
        return E_MISSING_SETTING_SIGN_BY_HASH;
    }

    if (p1 != 0x00) {
        return E_INCORRECT_P1_P2;
    }
    /* Do not overlay a hash-only review on a partially built full TIP-712
     * context (or any other signing session). */
    if ((appState != APP_STATE_IDLE) ||
        (tip712_get_phase() != TIP712_PHASE_NONE)) {
        return SWO_COMMAND_NOT_ALLOWED;
    }
    if (dataLength < 1) {
        return E_INCORRECT_DATA;
    }
    tmpCtx.messageSigningContext712.pathLength = workBuffer[0];
    if ((tmpCtx.messageSigningContext712.pathLength < 0x01) ||
        (tmpCtx.messageSigningContext712.pathLength > MAX_BIP32_PATH)) {
        return E_INCORRECT_DATA;
    }
    workBuffer++;
    dataLength--;
    for (i = 0; i < tmpCtx.messageSigningContext712.pathLength; i++) {
        if (dataLength < 4) {
            return E_INCORRECT_DATA;
        }
        tmpCtx.messageSigningContext712.bip32Path[i] = U4BE(workBuffer, 0);
        workBuffer += 4;
        dataLength -= 4;
    }
    if (dataLength != HASH_SIZE * 2) {
        return E_INCORRECT_DATA;
    }
    memmove(tmpCtx.messageSigningContext712.domainHash, workBuffer, HASH_SIZE);
    memmove(tmpCtx.messageSigningContext712.messageHash, workBuffer + HASH_SIZE, HASH_SIZE);

    if (!tip712_mark_legacy_reviewing()) {
        return SWO_COMMAND_NOT_ALLOWED;
    }
    LEDGER_ASSERT(appState == APP_STATE_IDLE, "idle required");
    appState = APP_STATE_SIGNING_TIP712;
    if (!ux_flow_display(APPROVAL_SIGN_TIP72_TRANSACTION, false)) {
        // The UI preparation helper already replied and reset the session.
        return APDU_NO_RESPONSE;
    }

    return APDU_NO_RESPONSE;
}
