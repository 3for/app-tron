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

extern void reset_app_context();

static uint16_t g_personal_message_apdu_count;

void personal_message_legacy_cleanup(void) {
    g_personal_message_apdu_count = 0;
}

bool personal_message_review_in_progress(void) {
    return appState == APP_STATE_REVIEWING_PERSONAL_MESSAGE;
}

int handleSignPersonalMessage(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    if (personal_message_review_in_progress()) {
        return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }
    if (p2 != 0) {
        if (appState != APP_STATE_IDLE) {
            reset_app_context();
        }
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        if (appState != APP_STATE_IDLE) {
            reset_app_context();
            return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
        }
        appState = APP_STATE_SIGNING_MESSAGE;

        off_t ret = read_bip32_path(workBuffer, dataLength, &tmpCtx.transactionContext.bip32_path);
        if (ret < 0) {
            reset_app_context();
            return io_send_sw(E_INCORRECT_BIP32_PATH);
        }
        workBuffer += ret;
        dataLength -= ret;

        // Message Length
        if (dataLength < sizeof(uint32_t)) {
            reset_app_context();
            return io_send_sw(E_INCORRECT_LENGTH);
        }
        txContent.dataBytes = U4BE(workBuffer, 0);
        if (txContent.dataBytes > MAX_PERSONAL_MESSAGE_LENGTH) {
            reset_app_context();
            return io_send_sw(E_INCORRECT_LENGTH);
        }
        workBuffer += 4;
        dataLength -= 4;
        g_personal_message_apdu_count = 1;

        // Initialize message header + length
        if ((cx_keccak_init_no_throw(&global_sha3, 256) != CX_OK) ||
            (cx_hash_no_throw((cx_hash_t *) &global_sha3,
                              0,
                              (const uint8_t *) SIGN_MAGIC,
                              sizeof(SIGN_MAGIC) - 1,
                              NULL,
                              0) != CX_OK)) {
            reset_app_context();
            return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
        }

        char tmp[11];
        snprintf(tmp, sizeof(tmp), "%u", (uint32_t) txContent.dataBytes);
        if (cx_hash_no_throw((cx_hash_t *) &global_sha3,
                             0,
                             (const uint8_t *) tmp,
                             strlen(tmp),
                             NULL,
                             0) != CX_OK) {
            reset_app_context();
            return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
        }

    } else if (p1 != P1_MORE) {
        reset_app_context();
        return io_send_sw(E_INCORRECT_P1_P2);
    } else if (appState != APP_STATE_SIGNING_MESSAGE) {
        PRINTF("Error: App not already in signing state!\n");
        reset_app_context();
        return io_send_sw(E_INCORRECT_DATA);
    }

    if (p1 == P1_MORE) {
        if ((g_personal_message_apdu_count >= MAX_PERSONAL_MESSAGE_APDUS) ||
            ((dataLength == 0) && (txContent.dataBytes != 0))) {
            reset_app_context();
            return io_send_sw(E_INCORRECT_LENGTH);
        }
        g_personal_message_apdu_count++;
    }
    if (dataLength > txContent.dataBytes) {
        reset_app_context();
        return io_send_sw(E_INCORRECT_LENGTH);
    }

    if (cx_hash_no_throw((cx_hash_t *) &global_sha3, 0, workBuffer, dataLength, NULL, 0) !=
        CX_OK) {
        reset_app_context();
        return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }
    txContent.dataBytes -= dataLength;
    if (txContent.dataBytes == 0) {
        if (cx_hash_no_throw((cx_hash_t *) &global_sha3,
                             CX_LAST,
                             NULL,
                             0,
                             tmpCtx.transactionContext.hash,
                             HASH_SIZE) != CX_OK) {
            reset_app_context();
            return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
        }
        format_hex(tmpCtx.transactionContext.hash,
                   sizeof(tmpCtx.transactionContext.hash),
                   strings.common.fullHash,
                   sizeof(strings.common.fullHash));
        publicKeyContext_t tmp_public_key_ctx;
        if (initPublicKeyContext(&tmpCtx.transactionContext.bip32_path,
                                 strings.common.fromAddress,
                                 &tmp_public_key_ctx) != 0) {
            reset_app_context();
            return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
        }

        appState = APP_STATE_REVIEWING_PERSONAL_MESSAGE;
        if (!ux_flow_display(APPROVAL_SIGN_PERSONAL_MESSAGE, false)) {
            // UI preparation failures already complete and reset the APDU.
            return 0;
        }

    } else {
        return io_send_sw(E_OK);
    }

    return 0;
}
