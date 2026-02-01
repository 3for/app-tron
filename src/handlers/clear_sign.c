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

#include "format.h"

#include "helpers.h"
#include "handlers.h"
#include "ui_review_menu.h"
#include "ui_globals.h"
#include "uint256.h"
#include "app_errors.h"
#include "parse.h"
#include "settings.h"
#include "trc_tokens.h"
#include "transaction_trigger_decode.h"
#ifdef HAVE_SWAP
#include "swap.h"
#include "handle_swap_sign_transaction.h"
#endif  // HAVE_SWAP

extern void reset_app_context();

static tron_stream_decoder_t clear_sign_decoder;

static bool clear_sign_decoder_complete(const tron_stream_decoder_t *dec) {
    return tron_stream_decoder_is_done(dec);
}

static bool clear_sign_parse_trigger_data(const tron_decode_result_t *res, txContent_t *content) {
    if (res == NULL || content == NULL) {
        return false;
    }

    if (!res->has_data) {
        return true;
    }

    if (res->data_len < 4 || res->data_prefix_len < 4) {
        return false;
    }

    content->customSelector = U4BE(res->data_prefix, 0);

    if (memcmp(res->data_prefix, SELECTOR[0], 4) == 0) {
        content->TRC20Method = 1;  // transfer(address,uint256)
    } else if (memcmp(res->data_prefix, SELECTOR[1], 4) == 0) {
        content->TRC20Method = 2;  // approve(address,uint256)
    } else {
        content->TRC20Method = 0;
        return ((res->data_len - 4) % 32 == 0);
    }

    if (res->data_len != (4 + 32 + 32) || res->data_prefix_len < (4 + 32 + 32)) {
        return false;
    }

    const uint8_t *arg1 = res->data_prefix + 4;
    memcpy(content->destination, arg1 + (32 - ADDRESS_SIZE), ADDRESS_SIZE);
    content->destination[0] = ADD_PRE_FIX_BYTE_MAINNET;

    const uint8_t *arg2 = res->data_prefix + 4 + 32;
    memmove(content->TRC20Amount, arg2, 32);

    return true;
}

static bool clear_sign_fill_txcontent(const tron_decode_result_t *res, txContent_t *content) {
    if (res == NULL || content == NULL) {
        return false;
    }

    if (!res->has_contract_type) {
        return false;
    }
    content->contractType = (contractType_e) res->contract_type;

    if (res->has_owner_address) {
        if (res->owner_address_len != ADDRESS_SIZE) {
            return false;
        }
        memcpy(content->account, res->owner_address, ADDRESS_SIZE);
    } else {
        return false;
    }

    if (res->has_contract_address) {
        if (res->contract_address_len != ADDRESS_SIZE) {
            return false;
        }
        memcpy(content->contractAddress, res->contract_address, ADDRESS_SIZE);
    } else {
        return false;
    }

    if (res->has_call_value) {
        content->amount[0] = (uint64_t) res->call_value;
    }

    if (res->has_custom_data) {
        content->dataBytes = res->custom_data_len;
    }

    if (res->has_permission_id) {
        content->permission_id = (uint8_t) res->permission_id;
    }

    if (!clear_sign_parse_trigger_data(res, content)) {
        return false;
    }

    tokenDefinition_t *trc20 = getKnownToken(content);
    if (trc20 == NULL) {
        content->TRC20Method = 0;
        return true;
    }

    content->decimals[0] = trc20->decimals;
    content->tokenNamesLength[0] = strlen(trc20->ticker) + 1;
    memmove(content->tokenNames[0], trc20->ticker, content->tokenNamesLength[0]);

    return true;
}

int handleClearSign(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    uint256_t uint256;
    bool data_warning;

    if (p2 != 0x00) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    // initialize context
    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        if (appState != APP_STATE_IDLE) {
            reset_app_context();
        }
        appState = APP_STATE_SIGNING;
        off_t ret = read_bip32_path(workBuffer, dataLength, &tmpCtx.transactionContext.bip32_path);
        if (ret < 0) {
            return io_send_sw(E_INCORRECT_BIP32_PATH);
        }
        workBuffer += ret;
        dataLength -= ret;

        if (dataLength < 4) {
            return io_send_sw(E_INCORRECT_LENGTH);
        }
        uint32_t total_len = U4BE(workBuffer, 0);
        workBuffer += 4;
        dataLength -= 4;

        initTx(&txContext, &txContent);
        customContractField = 0;
        tron_stream_decoder_init_raw(&clear_sign_decoder, total_len);

    } else if ((p1 != P1_MORE) && (p1 != P1_LAST)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    if (p1 == P1_MORE && appState != APP_STATE_SIGNING) {
        PRINTF("Signature not initialized\n");
        return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }

    // Context must be initialized first
    if (!txContext.initialized) {
        PRINTF("Context not initialized\n");
        // NOTE: if txContext is not initialized, then there must be seq errors in P1/P2.
        return io_send_sw(E_INCORRECT_P1_P2);
    }
    // hash data
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &txContext.sha2, 0, workBuffer, dataLength, NULL, 32));

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if (G_swap_response_ready) {
            // Safety against trying to make the app sign multiple TX
            // This code should never be triggered as the app is supposed to exit after
            // sending the signed transaction
            PRINTF("Safety against double signing triggered\n");
            os_sched_exit(-1);
        } else {
            // We will quit the app after this transaction, whether it succeeds or fails
            PRINTF("Swap response is ready, the app will quit after the next send\n");
            G_swap_response_ready = true;
        }
    }
#endif

    // process buffer
    if (!tron_stream_decoder_feed(&clear_sign_decoder, workBuffer, dataLength)) {
        return io_send_sw(E_INCORRECT_DATA);
    }

    if (p1 != P1_LAST && p1 != P1_SIGN) {
        return io_send_sw(E_OK);
    }

    if (!clear_sign_decoder_complete(&clear_sign_decoder)) {
        return io_send_sw(E_INCORRECT_DATA);
    }

    if (!clear_sign_fill_txcontent(&clear_sign_decoder.result, &txContent)) {
        return io_send_sw(E_INCORRECT_DATA);
    }

    if (!HAS_SETTING(S_DATA_ALLOWED) && txContent.dataBytes != 0) {
#ifdef HAVE_SWAP
        if (G_called_from_swap) {
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }
#endif
        return io_send_sw(E_MISSING_SETTING_DATA_ALLOWED);
    }

    // Last data hash
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &txContext.sha2,
                               CX_LAST,
                               workBuffer,
                               0,
                               tmpCtx.transactionContext.hash,
                               32));

    if (txContent.permission_id > 0) {
        PRINTF("Set permission_id...\n");
        snprintf((char *) fromAddress, 5, "P%d - ", txContent.permission_id);
        getBase58FromAddress(txContent.account, fromAddress + 4, HAS_SETTING(S_TRUNCATE_ADDRESS));
    } else {
        PRINTF("Regular transaction...\n");
        getBase58FromAddress(txContent.account, fromAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));
    }

    data_warning = ((txContent.dataBytes > 0) ? true : false);

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if (txContent.contractType != TRIGGERSMARTCONTRACT) {  // TRC20 Transfer
            PRINTF("Refused contract type when in SWAP mode\n");
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }

        if (txContent.TRC20Method != 1) {
            // Only transfer method allowed for TRC20
            PRINTF("Refused method type when in SWAP mode\n");
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }

        if (data_warning) {
            PRINTF("Refused data warning when in SWAP mode\n");
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }
    }
#endif  // HAVE_SWAP

    if (txContent.contractType != TRIGGERSMARTCONTRACT) {
        return io_send_sw(E_INCORRECT_DATA);
    }

    strcpy(TRC20ActionSendAllow, "To");
    if (txContent.TRC20Method == 1) {
        strcpy(TRC20Action, "Asset");
    } else if (txContent.TRC20Method == 2) {
        strcpy(TRC20ActionSendAllow, "Allow");
        strcpy(TRC20Action, "Approve");
    } else {
        if (!HAS_SETTING(S_CUSTOM_CONTRACT)) {
            return io_send_sw(E_MISSING_SETTING_CUSTOM_CONTRACT);
        }
        customContractField = 1;

        getBase58FromAddress(txContent.contractAddress,
                             fullContract,
                             HAS_SETTING(S_TRUNCATE_ADDRESS));
        snprintf((char *) TRC20Action, sizeof(TRC20Action), "%08x", txContent.customSelector);
        G_io_apdu_buffer[0] = '\0';
        G_io_apdu_buffer[100] = '\0';
        toAddress[0] = '\0';
        if (txContent.amount[0] > 0 && txContent.amount[1] > 0) {
            return io_send_sw(E_INCORRECT_DATA);
        }
        // call has value
        if (txContent.amount[0] > 0) {
            strcpy(toAddress, "TRX");
            print_amount(txContent.amount[0], (void *) G_io_apdu_buffer, 100, SUN_DIG);
            customContractField |= (1 << 0x05);
            customContractField |= (1 << 0x06);
        } else if (txContent.amount[1] > 0) {
            memcpy(toAddress, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);
            print_amount(txContent.amount[1], (void *) G_io_apdu_buffer, 100, 0);
            customContractField |= (1 << 0x05);
            customContractField |= (1 << 0x06);
        } else {
            strcpy(toAddress, "-");
            strlcpy((char *) G_io_apdu_buffer, "0", sizeof(G_io_apdu_buffer));
        }

        // approve custom contract
        ux_flow_display(APPROVAL_CUSTOM_CONTRACT, data_warning);

        return 0;
    }

    convertUint256BE(txContent.TRC20Amount, 32, &uint256);
    tostring256(&uint256, 10, (char *) G_io_apdu_buffer + 100, 100);
    if (!adjustDecimals((char *) G_io_apdu_buffer + 100,
                        strlen((const char *) G_io_apdu_buffer + 100),
                        (char *) G_io_apdu_buffer,
                        100,
                        txContent.decimals[0])) {
        return io_send_sw(E_INCORRECT_LENGTH);
    }

    getBase58FromAddress(txContent.destination, toAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));

    // get token name if any
    memcpy(fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);
#ifdef HAVE_SWAP
    // If we are in swap context, do not redisplay the message data
    // Instead, ensure they are identical with what was previously displayed
    if (G_called_from_swap) {
        if (swap_check_validity((char *) G_io_apdu_buffer,  // Amount
                                fullContract,               // Token name
                                TRC20ActionSendAllow,       // "Send To"
                                toAddress)) {
            PRINTF("Signing valid swap transaction\n");
            ui_callback_tx_ok(false);
        } else {
            PRINTF("Refused signing incorrect Swap transaction\n");
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }
    } else {
        ux_flow_display(APPROVAL_TRANSFER, data_warning);
    }
#else   // HAVE_SWAP
    ux_flow_display(APPROVAL_TRANSFER, data_warning);
#endif  // HAVE_SWAP

    return 0;
}
