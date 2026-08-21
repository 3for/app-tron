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
#include "handlers.h"
#include "parse.h"
#include "ui_globals.h"
#include "settings.h"

int handleSignTIP712Message(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    if (!HAS_SETTING(S_SIGN_BY_HASH)) {
        return io_send_sw(E_MISSING_SETTING_SIGN_BY_HASH);
    }

    if ((p1 != 00) || (p2 != 00)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }
    bip32_path_t bip32_path = {0};
    off_t path_size = read_bip32_path(workBuffer, dataLength, &bip32_path);
    if (path_size < 0) {
        return io_send_sw(E_INCORRECT_BIP32_PATH);
    }
    workBuffer += path_size;
    dataLength -= path_size;

    if (dataLength != HASH_SIZE * 2) {
        return io_send_sw(E_INCORRECT_LENGTH);
    }

    if (initPublicKeyContext(&bip32_path, messageSigningContext712.signerAddress) != 0) {
        return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }

    messageSigningContext712.bip32_path = bip32_path;
    memmove(messageSigningContext712.domainHash, workBuffer, HASH_SIZE);
    memmove(messageSigningContext712.messageHash, workBuffer + HASH_SIZE, HASH_SIZE);

    ux_flow_display(APPROVAL_SIGN_TIP72_TRANSACTION, false);

    return 0;
}
