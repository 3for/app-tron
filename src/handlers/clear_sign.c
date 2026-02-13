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
#include "os_io_seproxyhal.h"

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

extern void reset_app_context();

static tron_stream_decoder_t clear_sign_decoder;

typedef struct {
    bool expect_external_plugin;
    bool plugin_initialized;
    bool plugin_active;
    uint8_t selector[SELECTOR_LENGTH];
    uint8_t selector_len;
    uint8_t parameter[INT256_LENGTH];
    uint8_t parameter_len;
    uint32_t parameter_offset;
    uint8_t expected_contract[ADDRESS_SIZE];
    uint8_t expected_selector[SELECTOR_LENGTH];
} clear_sign_plugin_stream_t;

static clear_sign_plugin_stream_t clear_sign_plugin_stream;

static void clear_sign_sync_partial_txcontent(const tron_decode_result_t *res, txContent_t *content) {
    if (res == NULL || content == NULL) {
        return;
    }

    content->contractType = TRIGGERSMARTCONTRACT;
    if (res->has_contract_type) {
        content->contractType = (contractType_e) res->contract_type;
    }
    if (res->has_owner_address && res->owner_address_len == ADDRESS_SIZE) {
        memcpy(content->account, res->owner_address, ADDRESS_SIZE);
    }
    if (res->has_contract_address && res->contract_address_len == ADDRESS_SIZE) {
        memcpy(content->contractAddress, res->contract_address, ADDRESS_SIZE);
    }
    if (res->has_call_value) {
        content->amount[0] = (uint64_t) res->call_value;
    }
    if (res->has_permission_id) {
        content->permission_id = (uint8_t) res->permission_id;
    }
}

static bool clear_sign_call_external_plugin(uint32_t message, void *parameters) {
    uint32_t params[3];

    if (pluginType != PLUGIN_TYPE_EXTERNAL || dataContext.tokenContext.pluginName[0] == '\0') {
        return true;
    }

    params[0] = (uint32_t) dataContext.tokenContext.pluginName;
    params[1] = message;
    params[2] = (uint32_t) parameters;

    BEGIN_TRY {
        TRY {
            os_lib_call(params);
        }
        CATCH_OTHER(e) {
            PRINTF("External plugin call failed (%d)\n", e);
            CLOSE_TRY;
            return false;
        }
        FINALLY {
        }
    }
    END_TRY;

    return true;
}

static bool clear_sign_external_plugin_init(size_t data_size) {
    ethPluginInitContract_t init = {0};

    init.interfaceVersion = ETH_PLUGIN_INTERFACE_VERSION_LATEST;
    init.txContent = &txContent;
    init.pluginContextLength = PLUGIN_CONTEXT_SIZE;
    init.selector = clear_sign_plugin_stream.selector;
    init.dataSize = data_size;
    init.bip32 = &tmpCtx.transactionContext.bip32_path;
    init.pluginContext = dataContext.tokenContext.pluginContext;
    init.result = ETH_PLUGIN_RESULT_ERROR;

    if (!clear_sign_call_external_plugin(ETH_PLUGIN_INIT_CONTRACT, &init)) {
        return false;
    }

    dataContext.tokenContext.pluginStatus = (uint8_t) init.result;
    if (init.result == ETH_PLUGIN_RESULT_OK) {
        clear_sign_plugin_stream.plugin_active = true;
        return true;
    }
    if (init.result == ETH_PLUGIN_RESULT_FALLBACK) {
        clear_sign_plugin_stream.plugin_active = false;
        return true;
    }

    PRINTF("External plugin init rejected (%d)\n", init.result);
    return false;
}

static bool clear_sign_external_plugin_provide_parameter(const uint8_t *parameter,
                                                         uint8_t parameter_size,
                                                         uint32_t parameter_offset) {
    ethPluginProvideParameter_t provide = {0};

    provide.txContent = &txContent;
    provide.parameter = parameter;
    provide.parameterOffset = parameter_offset;
    provide.pluginContext = dataContext.tokenContext.pluginContext;
    provide.parameter_size = parameter_size;
    provide.result = ETH_PLUGIN_RESULT_ERROR;

    if (!clear_sign_call_external_plugin(ETH_PLUGIN_PROVIDE_PARAMETER, &provide)) {
        return false;
    }

    dataContext.tokenContext.pluginStatus = (uint8_t) provide.result;
    if (provide.result == ETH_PLUGIN_RESULT_OK) {
        return true;
    }
    if (provide.result == ETH_PLUGIN_RESULT_FALLBACK) {
        clear_sign_plugin_stream.plugin_active = false;
        return true;
    }

    PRINTF("External plugin parameter rejected (%d)\n", provide.result);
    return false;
}

static bool clear_sign_external_plugin_finalize(ethPluginFinalize_t *finalize) {
    if (finalize == NULL) {
        return false;
    }

    memset(finalize, 0, sizeof(*finalize));

    if (!clear_sign_plugin_stream.plugin_initialized || !clear_sign_plugin_stream.plugin_active) {
        finalize->result = ETH_PLUGIN_RESULT_FALLBACK;
        return true;
    }

    finalize->txContent = &txContent;
    finalize->pluginContext = dataContext.tokenContext.pluginContext;
    finalize->result = ETH_PLUGIN_RESULT_ERROR;

    if (!clear_sign_call_external_plugin(ETH_PLUGIN_FINALIZE, finalize)) {
        return false;
    }

    dataContext.tokenContext.pluginStatus = (uint8_t) finalize->result;
    if (finalize->result == ETH_PLUGIN_RESULT_FALLBACK) {
        clear_sign_plugin_stream.plugin_active = false;
        return true;
    }
    if (finalize->result <= ETH_PLUGIN_RESULT_UNSUCCESSFUL) {
        PRINTF("External plugin finalize rejected (%d)\n", finalize->result);
        return false;
    }

    return true;
}

static bool clear_sign_external_plugin_provide_info(const ethPluginFinalize_t *finalize,
                                                    ethPluginProvideInfo_t *provide) {
    if (provide == NULL) {
        return false;
    }

    memset(provide, 0, sizeof(*provide));
    provide->result = ETH_PLUGIN_RESULT_FALLBACK;

    if (finalize == NULL) {
        return false;
    }

    provide->result = finalize->result;

    if (!clear_sign_plugin_stream.plugin_initialized || !clear_sign_plugin_stream.plugin_active) {
        return true;
    }

    if ((finalize->tokenLookup1 == NULL) && (finalize->tokenLookup2 == NULL)) {
        return true;
    }

    provide->txContent = &txContent;
    provide->pluginContext = dataContext.tokenContext.pluginContext;
    provide->result = ETH_PLUGIN_RESULT_ERROR;
    provide->item1 = NULL;
    provide->item2 = NULL;

    if (finalize->tokenLookup1 != NULL) {
        PRINTF("Lookup1: %.*H\n", ADDRESS_LENGTH, finalize->tokenLookup1);
        provide->item1 = get_asset_info_by_addr(finalize->tokenLookup1);
        if (provide->item1 != NULL) {
            PRINTF("Token1 ticker: %s\n", provide->item1->token.ticker);
        }
    }
    if (finalize->tokenLookup2 != NULL) {
        PRINTF("Lookup2: %.*H\n", ADDRESS_LENGTH, finalize->tokenLookup2);
        provide->item2 = get_asset_info_by_addr(finalize->tokenLookup2);
        if (provide->item2 != NULL) {
            PRINTF("Token2 ticker: %s\n", provide->item2->token.ticker);
        }
    }

    if (!clear_sign_call_external_plugin(ETH_PLUGIN_PROVIDE_INFO, provide)) {
        return false;
    }

    dataContext.tokenContext.pluginStatus = (uint8_t) provide->result;
    if (provide->result <= ETH_PLUGIN_RESULT_UNSUCCESSFUL) {
        PRINTF("Plugin provide token call failed (%d)\n", provide->result);
        return false;
    }
    if (provide->result == ETH_PLUGIN_RESULT_FALLBACK) {
        clear_sign_plugin_stream.plugin_active = false;
    }

    return true;
}

static bool clear_sign_plugin_flush_parameter(void) {
    if (clear_sign_plugin_stream.parameter_len == 0) {
        return true;
    }

    if (clear_sign_plugin_stream.plugin_initialized && clear_sign_plugin_stream.plugin_active) {
        if (!clear_sign_external_plugin_provide_parameter(clear_sign_plugin_stream.parameter,
                                                          clear_sign_plugin_stream.parameter_len,
                                                          clear_sign_plugin_stream.parameter_offset)) {
            return false;
        }
        clear_sign_plugin_stream.parameter_offset += clear_sign_plugin_stream.parameter_len;
        dataContext.tokenContext.fieldIndex++;
    }

    clear_sign_plugin_stream.parameter_len = 0;
    dataContext.tokenContext.fieldOffset = 0;
    return true;
}

static bool clear_sign_plugin_feed_data_chunk(void *ctx,
                                              const uint8_t *chunk,
                                              size_t chunk_len,
                                              size_t chunk_offset,
                                              size_t total_len) {
    UNUSED(ctx);

    if (chunk == NULL || chunk_len == 0) {
        return true;
    }

    for (size_t i = 0; i < chunk_len; i++) {
        const uint8_t byte = chunk[i];
        const bool is_last_byte = ((chunk_offset + i + 1U) == total_len);

        if (clear_sign_plugin_stream.selector_len < SELECTOR_LENGTH) {
            clear_sign_plugin_stream.selector[clear_sign_plugin_stream.selector_len++] = byte;
            if (clear_sign_plugin_stream.selector_len == SELECTOR_LENGTH) {
                clear_sign_plugin_stream.parameter_offset = SELECTOR_LENGTH;
                if (clear_sign_plugin_stream.expect_external_plugin) {
                    bool contract_match = true;

                    if (clear_sign_decoder.result.has_contract_address &&
                        clear_sign_decoder.result.contract_address_len == ADDRESS_SIZE) {
                        contract_match =
                            (memcmp(clear_sign_decoder.result.contract_address,
                                    clear_sign_plugin_stream.expected_contract,
                                    ADDRESS_SIZE) == 0);
                    }

                    if (!contract_match ||
                        memcmp(clear_sign_plugin_stream.selector,
                               clear_sign_plugin_stream.expected_selector,
                               SELECTOR_LENGTH) != 0) {
                        clear_sign_plugin_stream.expect_external_plugin = false;
                    } else {
                        clear_sign_sync_partial_txcontent(&clear_sign_decoder.result, &txContent);
                        if (!clear_sign_external_plugin_init(total_len)) {
                            return false;
                        }
                        clear_sign_plugin_stream.plugin_initialized = true;
                    }
                }
            }
        } else {
            if (clear_sign_plugin_stream.plugin_initialized && clear_sign_plugin_stream.plugin_active) {
                clear_sign_plugin_stream.parameter[clear_sign_plugin_stream.parameter_len++] = byte;
                dataContext.tokenContext.fieldOffset = clear_sign_plugin_stream.parameter_len;
                if (clear_sign_plugin_stream.parameter_len == INT256_LENGTH) {
                    if (!clear_sign_external_plugin_provide_parameter(
                            clear_sign_plugin_stream.parameter,
                            INT256_LENGTH,
                            clear_sign_plugin_stream.parameter_offset)) {
                        return false;
                    }
                    clear_sign_plugin_stream.parameter_offset += INT256_LENGTH;
                    clear_sign_plugin_stream.parameter_len = 0;
                    dataContext.tokenContext.fieldOffset = 0;
                    dataContext.tokenContext.fieldIndex++;
                }
            }
        }

        if (is_last_byte) {
            if (!clear_sign_plugin_flush_parameter()) {
                return false;
            }
        }
    }

    return true;
}

static void clear_sign_plugin_stream_reset(void) {
    memset(&clear_sign_plugin_stream, 0, sizeof(clear_sign_plugin_stream));

    dataContext.tokenContext.fieldIndex = 0;
    dataContext.tokenContext.fieldOffset = 0;
    dataContext.tokenContext.pluginStatus = ETH_PLUGIN_RESULT_UNAVAILABLE;

    if (pluginType == PLUGIN_TYPE_EXTERNAL && dataContext.tokenContext.pluginName[0] != '\0') {
        clear_sign_plugin_stream.expect_external_plugin = true;
        memcpy(clear_sign_plugin_stream.expected_contract,
               dataContext.tokenContext.contractAddress,
               ADDRESS_SIZE);
        memcpy(clear_sign_plugin_stream.expected_selector,
               dataContext.tokenContext.methodSelector,
               SELECTOR_LENGTH);
    }
}

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
        return true;
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
    ethPluginFinalize_t plugin_finalize;
    ethPluginProvideInfo_t plugin_provide_info;

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
        clear_sign_plugin_stream_reset();
        tron_stream_decoder_set_trigger_data_observer(&clear_sign_decoder,
                                                      clear_sign_plugin_feed_data_chunk,
                                                      NULL);

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
        return io_send_sw(E_MISSING_SETTING_DATA_ALLOWED);
    }

    if (!clear_sign_external_plugin_finalize(&plugin_finalize)) {
        return io_send_sw(E_INCORRECT_DATA);
    }
    if (!clear_sign_external_plugin_provide_info(&plugin_finalize, &plugin_provide_info)) {
        return io_send_sw(E_INCORRECT_DATA);
    }
    plugin_finalize.result = plugin_provide_info.result;
    if (plugin_finalize.result != ETH_PLUGIN_RESULT_FALLBACK) {
        PRINTF("pluginFinalize.result %d successful\n", plugin_finalize.result);
        switch (plugin_finalize.uiType) {
            case ETH_UI_TYPE_GENERIC:
                dataContext.tokenContext.pluginUiMaxItems =
                    plugin_finalize.numScreens + plugin_provide_info.additionalScreens;
                break;
            case ETH_UI_TYPE_AMOUNT_ADDRESS:
            default:
                PRINTF("ui type %d not supported\n", plugin_finalize.uiType);
                return io_send_sw(E_INCORRECT_DATA);
        }
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

    ux_flow_display(APPROVAL_TRANSFER, data_warning);

    return 0;
}
