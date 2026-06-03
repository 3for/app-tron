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
#include "app_errors.h"
#include "app_mem_utils.h"
#include "parse.h"
#include "settings.h"
#include "transaction_trigger_decode.h"

extern void reset_app_context();

static tron_stream_decoder_t *tron_stream_decoder = NULL;

typedef struct {
    extraInfo_t *item1;
    extraInfo_t *item2;
} external_plugin_ui_info_t;

typedef struct {
    bool ready;
    bool has_contract_id;
    uint8_t item_count;
    char g_titleMsg[SHARED_CTX_FIELD_1_SIZE];
    char g_finishMsg[SHARED_CTX_FIELD_1_SIZE];
    char contract_name[SHARED_CTX_FIELD_2_SIZE];
    char contract_version[SHARED_CTX_FIELD_2_SIZE];
    char title[EXTERNAL_PLUGIN_UI_MAX_ITEMS][SHARED_CTX_FIELD_2_SIZE];
    char msg[EXTERNAL_PLUGIN_UI_MAX_ITEMS][SHARED_CTX_FIELD_1_SIZE];
} external_plugin_ui_cache_t;

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
} external_plugin_stream_t;

static external_plugin_stream_t external_plugin_stream;
static external_plugin_ui_info_t external_plugin_ui_info;
static external_plugin_ui_cache_t *external_plugin_ui_cache = NULL;
static uint16_t external_plugin_stream_failure_sw;

static uint16_t external_plugin_status_to_sw(uint8_t plugin_status) {
    if (plugin_status == TRON_PLUGIN_RESULT_UNAVAILABLE) {
        return E_PLUGIN_NOT_FOUND;
    }
    if (plugin_status == TRON_PLUGIN_RESULT_FALLBACK) {
        return E_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    if (plugin_status <= TRON_PLUGIN_RESULT_UNSUCCESSFUL) {
        return E_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    return E_INCORRECT_DATA;
}

static uint16_t external_plugin_failure_sw(void) {
    return external_plugin_status_to_sw(dataContext.tokenContext.pluginStatus);
}

static void record_plugin_failure(void) {
    external_plugin_stream_failure_sw = external_plugin_failure_sw();
}

static void sync_partial_txcontent(const tron_decode_result_t *res, txContent_t *content) {
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

static bool call_external_plugin(uint32_t message, void *parameters) {
    uintptr_t params[3];

    if (pluginType != PLUGIN_TYPE_EXTERNAL || dataContext.tokenContext.pluginName[0] == '\0') {
        return true;
    }

    params[0] = (uintptr_t) dataContext.tokenContext.pluginName;
    params[1] = (uintptr_t) message;
    params[2] = (uintptr_t) parameters;

    BEGIN_TRY {
        TRY {
            os_lib_call(params);
        }
        CATCH_OTHER(e) {
            (void) e;
            PRINTF("External plugin call failed (%d)\n", e);
            dataContext.tokenContext.pluginStatus = TRON_PLUGIN_RESULT_UNAVAILABLE;
            CLOSE_TRY;
            return false;
        }
        FINALLY {
        }
    }
    END_TRY;

    return true;
}

static bool external_plugin_init(size_t data_size) {
    tronPluginInitContract_t init = {0};

    init.interfaceVersion = TRON_PLUGIN_INTERFACE_VERSION_LATEST;
    init.txContent = &txContent;
    init.pluginContextLength = PLUGIN_CONTEXT_SIZE;
    init.selector = external_plugin_stream.selector;
    init.dataSize = data_size;
    init.bip32 = &tmpCtx.transactionContext.bip32_path;
    init.pluginContext = dataContext.tokenContext.pluginContext;
    init.result = TRON_PLUGIN_RESULT_ERROR;

    if (!call_external_plugin(TRON_PLUGIN_INIT_CONTRACT, &init)) {
        return false;
    }

    dataContext.tokenContext.pluginStatus = (uint8_t) init.result;
    if (init.result == TRON_PLUGIN_RESULT_OK) {
        external_plugin_stream.plugin_active = true;
        return true;
    }
    if (init.result == TRON_PLUGIN_RESULT_FALLBACK) {
        PRINTF("External plugin init fallback (%d)\n", init.result);
        return false;
    }

    PRINTF("External plugin init rejected (%d)\n", init.result);
    return false;
}

static bool external_plugin_provide_parameter(const uint8_t *parameter,
                                              uint8_t parameter_size,
                                              uint32_t parameter_offset) {
    tronPluginProvideParameter_t provide = {0};

    provide.txContent = &txContent;
    provide.parameter = parameter;
    provide.parameterOffset = parameter_offset;
    provide.pluginContext = dataContext.tokenContext.pluginContext;
    provide.parameter_size = parameter_size;
    provide.result = TRON_PLUGIN_RESULT_ERROR;

    if (!call_external_plugin(TRON_PLUGIN_PROVIDE_PARAMETER, &provide)) {
        return false;
    }

    dataContext.tokenContext.pluginStatus = (uint8_t) provide.result;
    if (provide.result == TRON_PLUGIN_RESULT_OK) {
        return true;
    }
    if (provide.result == TRON_PLUGIN_RESULT_FALLBACK) {
        PRINTF("External plugin provide parameter fallback (%d)\n", provide.result);
        return false;
    }

    PRINTF("External plugin parameter rejected (%d)\n", provide.result);
    return false;
}

static bool external_plugin_finalize(tronPluginFinalize_t *finalize) {
    if (finalize == NULL) {
        return false;
    }

    memset(finalize, 0, sizeof(*finalize));

    if (!external_plugin_stream.plugin_initialized || !external_plugin_stream.plugin_active) {
        finalize->result = TRON_PLUGIN_RESULT_FALLBACK;
        return true;
    }

    finalize->txContent = &txContent;
    finalize->pluginContext = dataContext.tokenContext.pluginContext;
    finalize->result = TRON_PLUGIN_RESULT_ERROR;

    if (!call_external_plugin(TRON_PLUGIN_FINALIZE, finalize)) {
        return false;
    }

    dataContext.tokenContext.pluginStatus = (uint8_t) finalize->result;
    if (finalize->result == TRON_PLUGIN_RESULT_FALLBACK) {
        PRINTF("External plugin finalize fallback (%d)\n", finalize->result);
        return false;
    }
    if (finalize->result <= TRON_PLUGIN_RESULT_UNSUCCESSFUL) {
        PRINTF("External plugin finalize rejected (%d)\n", finalize->result);
        return false;
    }

    return true;
}

static bool external_plugin_provide_info(const tronPluginFinalize_t *finalize,
                                         tronPluginProvideInfo_t *provide) {
    if (provide == NULL) {
        return false;
    }

    memset(provide, 0, sizeof(*provide));
    provide->result = TRON_PLUGIN_RESULT_FALLBACK;

    if (finalize == NULL) {
        return false;
    }

    provide->result = finalize->result;

    external_plugin_ui_info.item1 = NULL;
    external_plugin_ui_info.item2 = NULL;

    if (!external_plugin_stream.plugin_initialized || !external_plugin_stream.plugin_active) {
        return true;
    }

    if ((finalize->tokenLookup1 == NULL) && (finalize->tokenLookup2 == NULL)) {
        return true;
    }

    provide->txContent = &txContent;
    provide->pluginContext = dataContext.tokenContext.pluginContext;
    provide->result = TRON_PLUGIN_RESULT_ERROR;
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

    if (!call_external_plugin(TRON_PLUGIN_PROVIDE_INFO, provide)) {
        return false;
    }

    dataContext.tokenContext.pluginStatus = (uint8_t) provide->result;
    if (provide->result <= TRON_PLUGIN_RESULT_UNSUCCESSFUL) {
        PRINTF("Plugin provide token call failed (%d)\n", provide->result);
        return false;
    }
    if (provide->result == TRON_PLUGIN_RESULT_FALLBACK) {
        PRINTF("Plugin provide info fallback (%d)\n", provide->result);
        return false;
    }

    external_plugin_ui_info.item1 = provide->item1;
    external_plugin_ui_info.item2 = provide->item2;

    return true;
}

static bool external_plugin_ui_cache_alloc(void) {
    if (external_plugin_ui_cache != NULL) {
        return true;
    }

    return APP_MEM_CALLOC((void **) &external_plugin_ui_cache,
                          sizeof(*external_plugin_ui_cache));
}

static void external_plugin_ui_cache_reset(void) {
    if (external_plugin_ui_cache != NULL) {
        memset(external_plugin_ui_cache, 0, sizeof(*external_plugin_ui_cache));
    }
}

static void external_plugin_ui_cache_cleanup(void) {
    APP_MEM_FREE_AND_NULL((void **) &external_plugin_ui_cache);
}

static void lowercase_ascii_inplace(char *s, size_t s_len) {
    if ((s == NULL) || (s_len == 0)) {
        return;
    }

    for (size_t i = 0; (i < s_len) && (s[i] != '\0'); i++) {
        if ((s[i] >= 'A') && (s[i] <= 'Z')) {
            s[i] = (char) (s[i] - 'A' + 'a');
        }
    }
}

static void external_plugin_prepare_title_msg(void) {
    if (external_plugin_ui_cache == NULL) {
        return;
    }

    if (!external_plugin_ui_cache->has_contract_id ||
        external_plugin_ui_cache->contract_name[0] == '\0') {
        char contract_addr[BASE58CHECK_ADDRESS_SIZE + 1];

        getBase58FromAddress(txContent.contractAddress,
                             contract_addr,
                             HAS_SETTING(S_TRUNCATE_ADDRESS));
        snprintf(external_plugin_ui_cache->g_titleMsg,
                 sizeof(external_plugin_ui_cache->g_titleMsg),
                 "%s %s",
                 contract_addr,
                 "-");
        snprintf(external_plugin_ui_cache->g_finishMsg,
                 sizeof(external_plugin_ui_cache->g_finishMsg),
                 "%s %s?",
                 contract_addr,
                 "-");
        return;
    }

    {
        char contract_version[SHARED_CTX_FIELD_2_SIZE];
        const char *title_prefix = "Review transaction";
        const char *finish_prefix = "Sign transaction";

        strlcpy(contract_version,
                external_plugin_ui_cache->contract_version,
                sizeof(contract_version));
        lowercase_ascii_inplace(contract_version, sizeof(contract_version));

        snprintf(external_plugin_ui_cache->g_titleMsg,
                 sizeof(external_plugin_ui_cache->g_titleMsg),
                 "%s to %s on %s",
                 title_prefix,
                 contract_version,
                 external_plugin_ui_cache->contract_name);
        snprintf(external_plugin_ui_cache->g_finishMsg,
                 sizeof(external_plugin_ui_cache->g_finishMsg),
                 "%s to %s on %s?",
                 finish_prefix,
                 contract_version,
                 external_plugin_ui_cache->contract_name);
    }
}

static bool external_plugin_query_contract_id_raw(char *name,
                                                  size_t name_len,
                                                  char *version,
                                                  size_t version_len) {
    tronQueryContractID_t query = {0};

    if ((name == NULL) || (version == NULL) || (name_len == 0) || (version_len == 0)) {
        return false;
    }

    name[0] = '\0';
    version[0] = '\0';

    if (!external_plugin_stream.plugin_initialized || !external_plugin_stream.plugin_active) {
        return false;
    }

    query.txContent = &txContent;
    query.name = name;
    query.nameLength = name_len;
    query.version = version;
    query.versionLength = version_len;
    query.pluginContext = dataContext.tokenContext.pluginContext;
    query.result = TRON_PLUGIN_RESULT_ERROR;

    if (!call_external_plugin(TRON_PLUGIN_QUERY_CONTRACT_ID, &query)) {
        return false;
    }

    dataContext.tokenContext.pluginStatus = (uint8_t) query.result;
    return query.result == TRON_PLUGIN_RESULT_OK;
}

bool external_plugin_get_cached_ui_items_count(uint8_t *count) {
    if (count == NULL) {
        return false;
    }

    *count = 0;

    if (external_plugin_ui_cache == NULL || !external_plugin_ui_cache->ready) {
        return false;
    }

    *count = external_plugin_ui_cache->item_count;
    return true;
}

bool external_plugin_get_cached_title_msg(char *title_msg, size_t title_msg_len) {
    if ((title_msg == NULL) || (title_msg_len == 0)) {
        return false;
    }

    title_msg[0] = '\0';

    if (external_plugin_ui_cache == NULL || !external_plugin_ui_cache->ready ||
        external_plugin_ui_cache->g_titleMsg[0] == '\0') {
        return false;
    }

    strlcpy(title_msg, external_plugin_ui_cache->g_titleMsg, title_msg_len);
    return true;
}

bool external_plugin_get_cached_finish_msg(char *finish_msg, size_t finish_msg_len) {
    if ((finish_msg == NULL) || (finish_msg_len == 0)) {
        return false;
    }

    finish_msg[0] = '\0';

    if (external_plugin_ui_cache == NULL || !external_plugin_ui_cache->ready ||
        external_plugin_ui_cache->g_finishMsg[0] == '\0') {
        return false;
    }

    strlcpy(finish_msg, external_plugin_ui_cache->g_finishMsg, finish_msg_len);
    return true;
}

const char *external_plugin_get_cached_title_msg_ref(void) {
    if (external_plugin_ui_cache == NULL || !external_plugin_ui_cache->ready ||
        external_plugin_ui_cache->g_titleMsg[0] == '\0') {
        return NULL;
    }

    return external_plugin_ui_cache->g_titleMsg;
}

const char *external_plugin_get_cached_finish_msg_ref(void) {
    if (external_plugin_ui_cache == NULL || !external_plugin_ui_cache->ready ||
        external_plugin_ui_cache->g_finishMsg[0] == '\0') {
        return NULL;
    }

    return external_plugin_ui_cache->g_finishMsg;
}

static bool external_plugin_query_contract_ui_raw(uint8_t screen_index,
                                                  char *title,
                                                  size_t title_len,
                                                  char *out_msg,
                                                  size_t out_msg_len) {
    tronQueryContractUI_t query = {0};

    if ((title == NULL) || (out_msg == NULL) || (title_len == 0) || (out_msg_len == 0)) {
        return false;
    }

    title[0] = '\0';
    out_msg[0] = '\0';

    if (!external_plugin_stream.plugin_initialized || !external_plugin_stream.plugin_active) {
        return false;
    }

    query.txContent = &txContent;
    query.item1 = external_plugin_ui_info.item1;
    query.item2 = external_plugin_ui_info.item2;
    strlcpy(query.network_ticker, chainConfig->coinName, sizeof(query.network_ticker));
    query.screenIndex = screen_index;
    query.title = title;
    query.titleLength = title_len;
    query.msg = out_msg;
    query.msgLength = out_msg_len;
    query.pluginContext = dataContext.tokenContext.pluginContext;
    query.result = TRON_PLUGIN_RESULT_ERROR;

    if (!call_external_plugin(TRON_PLUGIN_QUERY_CONTRACT_UI, &query)) {
        return false;
    }

    dataContext.tokenContext.pluginStatus = (uint8_t) query.result;
    return query.result == TRON_PLUGIN_RESULT_OK;
}

bool external_plugin_get_cached_contract_ui(uint8_t screen_index,
                                            char *title,
                                            size_t title_len,
                                            char *out_msg,
                                            size_t out_msg_len) {
    if ((title == NULL) || (out_msg == NULL) || (title_len == 0) || (out_msg_len == 0)) {
        return false;
    }

    title[0] = '\0';
    out_msg[0] = '\0';

    if (external_plugin_ui_cache == NULL || !external_plugin_ui_cache->ready ||
        (screen_index >= external_plugin_ui_cache->item_count)) {
        return false;
    }

    strlcpy(title, external_plugin_ui_cache->title[screen_index], title_len);
    strlcpy(out_msg, external_plugin_ui_cache->msg[screen_index], out_msg_len);
    return true;
}

bool external_plugin_get_cached_contract_ui_ref(uint8_t screen_index,
                                                const char **title,
                                                const char **out_msg) {
    if ((title == NULL) || (out_msg == NULL)) {
        return false;
    }

    *title = NULL;
    *out_msg = NULL;

    if (external_plugin_ui_cache == NULL || !external_plugin_ui_cache->ready ||
        (screen_index >= external_plugin_ui_cache->item_count)) {
        return false;
    }

    *title = external_plugin_ui_cache->title[screen_index];
    *out_msg = external_plugin_ui_cache->msg[screen_index];
    return true;
}

static uint16_t prepare_plugin_ui_cache(void) {
    uint8_t plugin_ui_items = dataContext.tokenContext.pluginUiMaxItems;

    if (!external_plugin_ui_cache_alloc()) {
        return APDU_RESPONSE_INSUFFICIENT_MEMORY;
    }

    external_plugin_ui_cache_reset();

    if (plugin_ui_items == 0) {
        PRINTF("Plugin UI items cannot be zero\n");
        return E_INCORRECT_DATA;
    }

    if (plugin_ui_items > EXTERNAL_PLUGIN_UI_MAX_ITEMS) {
        PRINTF("Plugin UI items exceed cache capacity (%u > %u)\n",
               (unsigned int) plugin_ui_items,
               (unsigned int) EXTERNAL_PLUGIN_UI_MAX_ITEMS);
        return E_INCORRECT_DATA;
    }

    if (!external_plugin_query_contract_id_raw(external_plugin_ui_cache->contract_name,
                                               sizeof(external_plugin_ui_cache->contract_name),
                                               external_plugin_ui_cache->contract_version,
                                               sizeof(external_plugin_ui_cache->contract_version))) {
        PRINTF("Plugin contract ID query failed\n");
        external_plugin_ui_cache_reset();
        return external_plugin_failure_sw();
    }
    external_plugin_ui_cache->has_contract_id = true;
    external_plugin_prepare_title_msg();

    for (uint8_t i = 0; i < plugin_ui_items; i++) {
        if (!external_plugin_query_contract_ui_raw(i,
                                                   external_plugin_ui_cache->title[i],
                                                   sizeof(external_plugin_ui_cache->title[i]),
                                                   external_plugin_ui_cache->msg[i],
                                                   sizeof(external_plugin_ui_cache->msg[i]))) {
            PRINTF("Plugin UI query failed at screen %u\n", (unsigned int) i);
            external_plugin_ui_cache_reset();
            return external_plugin_failure_sw();
        }
    }

    external_plugin_ui_cache->item_count = plugin_ui_items;
    external_plugin_ui_cache->ready = true;
    return E_OK;
}

static bool external_plugin_flush_parameter(void) {
    if (external_plugin_stream.parameter_len == 0) {
        return true;
    }

    if (external_plugin_stream.plugin_initialized && external_plugin_stream.plugin_active) {
        if (!external_plugin_provide_parameter(external_plugin_stream.parameter,
                                               external_plugin_stream.parameter_len,
                                               external_plugin_stream.parameter_offset)) {
            record_plugin_failure();
            return false;
        }
        external_plugin_stream.parameter_offset += external_plugin_stream.parameter_len;
        dataContext.tokenContext.fieldIndex++;
    }

    external_plugin_stream.parameter_len = 0;
    dataContext.tokenContext.fieldOffset = 0;
    return true;
}

static bool external_plugin_feed_data_chunk(void *ctx,
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

        if (external_plugin_stream.selector_len < SELECTOR_LENGTH) {
            external_plugin_stream.selector[external_plugin_stream.selector_len++] = byte;
            if (external_plugin_stream.selector_len == SELECTOR_LENGTH) {
                external_plugin_stream.parameter_offset = SELECTOR_LENGTH;
                if (external_plugin_stream.expect_external_plugin) {
                    bool contract_match = true;

                    if (tron_stream_decoder == NULL) {
                        return false;
                    }
                    if (tron_stream_decoder->result.has_contract_address &&
                        tron_stream_decoder->result.contract_address_len == ADDRESS_SIZE) {
                        contract_match = (memcmp(tron_stream_decoder->result.contract_address,
                                                 external_plugin_stream.expected_contract,
                                                 ADDRESS_SIZE) == 0);
                    }

                    if (!contract_match || memcmp(external_plugin_stream.selector,
                                                  external_plugin_stream.expected_selector,
                                                  SELECTOR_LENGTH) != 0) {
                        external_plugin_stream.expect_external_plugin = false;
                    } else {
                        sync_partial_txcontent(&tron_stream_decoder->result, &txContent);
                        if (!external_plugin_init(total_len)) {
                            record_plugin_failure();
                            return false;
                        }
                        external_plugin_stream.plugin_initialized = true;
                    }
                }
            }
        } else {
            if (external_plugin_stream.plugin_initialized && external_plugin_stream.plugin_active) {
                external_plugin_stream.parameter[external_plugin_stream.parameter_len++] = byte;
                dataContext.tokenContext.fieldOffset = external_plugin_stream.parameter_len;
                if (external_plugin_stream.parameter_len == INT256_LENGTH) {
                    if (!external_plugin_provide_parameter(
                            external_plugin_stream.parameter,
                            INT256_LENGTH,
                            external_plugin_stream.parameter_offset)) {
                        record_plugin_failure();
                        return false;
                    }
                    external_plugin_stream.parameter_offset += INT256_LENGTH;
                    external_plugin_stream.parameter_len = 0;
                    dataContext.tokenContext.fieldOffset = 0;
                    dataContext.tokenContext.fieldIndex++;
                }
            }
        }

        if (is_last_byte) {
            if (!external_plugin_flush_parameter()) {
                return false;
            }
        }
    }

    return true;
}

static void external_plugin_stream_reset(void) {
    memset(&external_plugin_stream, 0, sizeof(external_plugin_stream));
    memset(&external_plugin_ui_info, 0, sizeof(external_plugin_ui_info));
    external_plugin_ui_cache_reset();
    external_plugin_stream_failure_sw = E_OK;

    dataContext.tokenContext.fieldIndex = 0;
    dataContext.tokenContext.fieldOffset = 0;
    dataContext.tokenContext.pluginUiMaxItems = 0;
    dataContext.tokenContext.pluginUiCurrentItem = 0;
    dataContext.tokenContext.pluginUiState = 0;
    dataContext.tokenContext.pluginStatus = TRON_PLUGIN_RESULT_UNAVAILABLE;

    if (pluginType == PLUGIN_TYPE_EXTERNAL && dataContext.tokenContext.pluginName[0] != '\0') {
        external_plugin_stream.expect_external_plugin = true;
        memcpy(external_plugin_stream.expected_contract,
               dataContext.tokenContext.contractAddress,
               ADDRESS_SIZE);
        memcpy(external_plugin_stream.expected_selector,
               dataContext.tokenContext.methodSelector,
               SELECTOR_LENGTH);
    }
}

static bool tron_stream_decoder_complete(const tron_stream_decoder_t *dec) {
    return tron_stream_decoder_is_done(dec);
}

void cleanupSignExternalPlugin(void) {
    APP_MEM_FREE_AND_NULL((void **) &tron_stream_decoder);
    external_plugin_ui_cache_cleanup();
}

static bool tron_stream_parse_trigger_data(const tron_decode_result_t *res, txContent_t *content) {
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

    return true;
}

static bool tron_stream_fill_txcontent(const tron_decode_result_t *res, txContent_t *content) {
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

    if (!tron_stream_parse_trigger_data(res, content)) {
        return false;
    }

    tokenDefinition_t *trc20 = getKnownToken(content);
    if (trc20 != NULL) {
        content->decimals[0] = trc20->decimals;
        content->tokenNamesLength[0] = strlen(trc20->ticker) + 1;
        memmove(content->tokenNames[0], trc20->ticker, content->tokenNamesLength[0]);
    }

    return true;
}

int handleSignExternalPlugin(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    tronPluginFinalize_t plugin_finalize;
    tronPluginProvideInfo_t plugin_provide_info;

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
        cleanupSignExternalPlugin();
        if (APP_MEM_CALLOC((void **) &tron_stream_decoder, sizeof(*tron_stream_decoder)) == false) {
            reset_app_context();
            return io_send_sw(APDU_RESPONSE_INSUFFICIENT_MEMORY);
        }
        tron_stream_decoder_init_raw(tron_stream_decoder, total_len);
        external_plugin_stream_reset();
        tron_stream_decoder_set_trigger_data_observer(tron_stream_decoder,
                                                      external_plugin_feed_data_chunk,
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
    if (!tron_stream_decoder_feed(tron_stream_decoder, workBuffer, dataLength)) {
        uint16_t sw = (external_plugin_stream_failure_sw != E_OK)
                          ? external_plugin_stream_failure_sw
                          : E_INCORRECT_DATA;
        reset_app_context();
        return io_send_sw(sw);
    }

    if (p1 != P1_LAST && p1 != P1_SIGN) {
        return io_send_sw(E_OK);
    }

    if (!tron_stream_decoder_complete(tron_stream_decoder)) {
        reset_app_context();
        return io_send_sw(E_INCORRECT_DATA);
    }

    if (!tron_stream_fill_txcontent(&tron_stream_decoder->result, &txContent)) {
        reset_app_context();
        return io_send_sw(E_INCORRECT_DATA);
    }
    APP_MEM_FREE_AND_NULL((void **) &tron_stream_decoder);

    if (!external_plugin_finalize(&plugin_finalize)) {
        reset_app_context();
        return io_send_sw(external_plugin_failure_sw());
    }
    if (!external_plugin_provide_info(&plugin_finalize, &plugin_provide_info)) {
        reset_app_context();
        return io_send_sw(external_plugin_failure_sw());
    }
    plugin_finalize.result = plugin_provide_info.result;
    if (plugin_finalize.result != TRON_PLUGIN_RESULT_FALLBACK) {
        PRINTF("pluginFinalize.result %d successful\n", plugin_finalize.result);
        switch (plugin_finalize.uiType) {
            case TRON_UI_TYPE_GENERIC:
                dataContext.tokenContext.pluginUiMaxItems =
                    plugin_finalize.numScreens + plugin_provide_info.additionalScreens;
                break;
            case TRON_UI_TYPE_AMOUNT_ADDRESS:
            default:
                PRINTF("ui type %d not supported\n", plugin_finalize.uiType);
                reset_app_context();
                return io_send_sw(E_INCORRECT_DATA);
        }
    }
    {
        const uint16_t sw = prepare_plugin_ui_cache();
        if (sw != E_OK) {
            PRINTF("Plugin query contract UI call failed\n");
            reset_app_context();
            return io_send_sw(sw);
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
        size_t prefix_len = 0U;
        int prefix_written;

        PRINTF("Set permission_id...\n");
        prefix_written = snprintf((char *) fromAddress,
                                  sizeof(fromAddress),
                                  "P%d - ",
                                  txContent.permission_id);
        if ((prefix_written > 0) &&
            ((size_t) prefix_written <=
             (sizeof(fromAddress) - (BASE58CHECK_ADDRESS_SIZE + 1U)))) {
            prefix_len = (size_t) prefix_written;
        } else {
            fromAddress[0] = '\0';
        }

        getBase58FromAddress(txContent.account,
                             fromAddress + prefix_len,
                             HAS_SETTING(S_TRUNCATE_ADDRESS));
    } else {
        PRINTF("Regular transaction...\n");
        getBase58FromAddress(txContent.account, fromAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));
    }

    if (txContent.contractType != TRIGGERSMARTCONTRACT) {
        reset_app_context();
        return io_send_sw(E_INCORRECT_DATA);
    }

    /* if (!HAS_SETTING(S_CUSTOM_CONTRACT)) {
        return io_send_sw(E_MISSING_SETTING_CUSTOM_CONTRACT);
    } */ //TODO. ZYD
    customContractField = 1;

    getBase58FromAddress(txContent.contractAddress, fullContract, HAS_SETTING(S_TRUNCATE_ADDRESS));
    snprintf((char *) TRC20Action, sizeof(TRC20Action), "%08x", txContent.customSelector);
    G_io_apdu_buffer[0] = '\0';
    G_io_apdu_buffer[100] = '\0';
    toAddress[0] = '\0';
    if (txContent.amount[0] > 0 && txContent.amount[1] > 0) {
        reset_app_context();
        return io_send_sw(E_INCORRECT_DATA);
    }
    // call has value
    if (txContent.amount[0] > 0) {
        strcpy(toAddress, "TRX");
        print_amount(txContent.amount[0], (void *) G_io_apdu_buffer, 100, SUN_DIG);
        customContractField |= (1 << 0x05);
        customContractField |= (1 << 0x06);
    } else if (txContent.amount[1] > 0) {
        size_t token_name_len = txContent.tokenNamesLength[0];

        if (token_name_len >= sizeof(toAddress)) {
            token_name_len = sizeof(toAddress) - 1U;
        }
        memcpy(toAddress, txContent.tokenNames[0], token_name_len);
        toAddress[token_name_len] = '\0';
        print_amount(txContent.amount[1], (void *) G_io_apdu_buffer, 100, 0);
        customContractField |= (1 << 0x05);
        customContractField |= (1 << 0x06);
    } else {
        strcpy(toAddress, "-");
        strlcpy((char *) G_io_apdu_buffer, "0", sizeof(G_io_apdu_buffer));
    }

    // approve clear sign custom contract
    // data_warning always false for clear sign case
    ux_flow_display(APPROVAL_SIGN_EXTERNAL_PLUGIN_CUSTOM_CONTRACT, false);

    return 0;
}
