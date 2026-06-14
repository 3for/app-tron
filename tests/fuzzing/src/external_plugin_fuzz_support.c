#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "app_errors.h"
#include "bip32_path_parser.h"
#include "common_utils.h"
#include "cx.h"
#include "apdu_constants.h"
#include "helpers.h"
#include "parse.h"
#include "public_keys.h"
#include "settings.h"
#include "tron_plugin_interface.h"
#include "ui_globals.h"
#include "ui_review_menu.h"

void reset_app_context(void);
extern bool g_fuzz_signature_valid;

volatile uint8_t customContractField;
char fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];
char toAddress[BASE58CHECK_ADDRESS_SIZE + 1];
char fullContract[MAX_TOKEN_LENGTH];
char TRC20Action[9];
uint8_t G_io_apdu_buffer[260];

int fuzz_os_lib_exception_code;
jmp_buf fuzz_os_lib_jmp_buf;

typedef struct {
    uint8_t settings;
    bool signature_valid;
    uint8_t presence_mode;
    uint8_t init_mode;
    uint8_t parameter_mode;
    uint8_t parameter_fail_cfg;
    uint8_t finalize_mode;
    uint8_t ui_type_mode;
    uint8_t num_screens;
    uint8_t token_lookup_mode;
    uint8_t provide_info_mode;
    uint8_t additional_screens;
    uint8_t query_contract_id_mode;
    bool empty_contract_name;
    bool empty_contract_version;
    uint8_t query_contract_ui_mode;
    uint8_t query_contract_ui_fail_index;
} external_plugin_fuzz_behavior_t;

static external_plugin_fuzz_behavior_t g_plugin_behavior;

static const uint8_t fuzz_lookup_known_1[ADDRESS_LENGTH] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
};
static const uint8_t fuzz_lookup_known_2[ADDRESS_LENGTH] = {
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
};
static const uint8_t fuzz_lookup_unknown[ADDRESS_LENGTH] = {
    0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
    0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
};

static tron_plugin_result_t fuzz_decode_plugin_result(uint8_t mode) {
    switch (mode & 0x03U) {
        case 0U:
            return TRON_PLUGIN_RESULT_OK;
        case 1U:
            return TRON_PLUGIN_RESULT_FALLBACK;
        case 2U:
            return TRON_PLUGIN_RESULT_UNAVAILABLE;
        default:
            return TRON_PLUGIN_RESULT_ERROR;
    }
}

static void fuzz_throw_os_lib_exception(int code) {
    fuzz_os_lib_exception_code = code;
    longjmp(fuzz_os_lib_jmp_buf, 1);
}

void init_external_plugin_fuzz_environment(const uint8_t *config, size_t config_len) {
    memset(&g_plugin_behavior, 0, sizeof(g_plugin_behavior));
    if ((config != NULL) && (config_len > 0U)) {
        g_plugin_behavior.settings = config[0];
    }
    if ((config != NULL) && (config_len > 1U)) {
        g_plugin_behavior.signature_valid = (config[1] & 0x01U) == 0U;
    } else {
        g_plugin_behavior.signature_valid = true;
    }
    if ((config != NULL) && (config_len > 2U)) {
        g_plugin_behavior.presence_mode = config[2];
    }
    if ((config != NULL) && (config_len > 3U)) {
        g_plugin_behavior.init_mode = config[3];
    }
    if ((config != NULL) && (config_len > 4U)) {
        g_plugin_behavior.parameter_mode = config[4];
    }
    if ((config != NULL) && (config_len > 5U)) {
        g_plugin_behavior.parameter_fail_cfg = config[5];
    }
    if ((config != NULL) && (config_len > 6U)) {
        g_plugin_behavior.finalize_mode = config[6];
    }
    if ((config != NULL) && (config_len > 7U)) {
        g_plugin_behavior.ui_type_mode = config[7];
    }
    if ((config != NULL) && (config_len > 8U)) {
        g_plugin_behavior.num_screens = config[8];
    }
    if ((config != NULL) && (config_len > 9U)) {
        g_plugin_behavior.token_lookup_mode = config[9];
    }
    if ((config != NULL) && (config_len > 10U)) {
        g_plugin_behavior.provide_info_mode = config[10];
    }
    if ((config != NULL) && (config_len > 11U)) {
        g_plugin_behavior.additional_screens = config[11];
    }
    if ((config != NULL) && (config_len > 12U)) {
        g_plugin_behavior.query_contract_id_mode = config[12];
    }
    if ((config != NULL) && (config_len > 13U)) {
        g_plugin_behavior.empty_contract_name = (config[13] & 0x01U) != 0U;
        g_plugin_behavior.empty_contract_version = (config[13] & 0x02U) != 0U;
    }
    if ((config != NULL) && (config_len > 14U)) {
        g_plugin_behavior.query_contract_ui_mode = config[14];
    }
    if ((config != NULL) && (config_len > 15U)) {
        g_plugin_behavior.query_contract_ui_fail_index = config[15];
    } else {
        g_plugin_behavior.query_contract_ui_fail_index = 0xFFU;
    }

    reset_app_context();
    fuzz_set_settings(g_plugin_behavior.settings);
    g_fuzz_signature_valid = g_plugin_behavior.signature_valid;
    fuzz_os_lib_exception_code = 0;
    ((chain_config_t *) chainConfig)->chainId = 0x2BU;
    strlcpy(((chain_config_t *) chainConfig)->coinName,
            "TRX",
            sizeof(((chain_config_t *) chainConfig)->coinName));
    memset((void *) &customContractField, 0, sizeof(customContractField));
    memset(fromAddress, 0, sizeof(fromAddress));
    memset(toAddress, 0, sizeof(toAddress));
    memset(fullContract, 0, sizeof(fullContract));
    memset(TRC20Action, 0, sizeof(TRC20Action));
    memset(G_io_apdu_buffer, 0, sizeof(G_io_apdu_buffer));
}

off_t read_bip32_path(const uint8_t *buffer, size_t length, bip32_path_t *path) {
    if (path == NULL) {
        return -1;
    }

    return read_bip32_path_words(buffer,
                                 length,
                                 &path->length,
                                 path->indices,
                                 MAX_BIP32_PATH);
}

void getBase58FromAddress(const uint8_t address[static ADDRESS_SIZE], char *out, bool truncate) {
    static const char hex[] = "0123456789abcdef";
    size_t offset = 0U;
    size_t bytes_to_show = truncate ? 4U : ADDRESS_SIZE;

    if (out == NULL) {
        return;
    }

    out[offset++] = 'T';
    for (size_t i = 0; (i < bytes_to_show) && (offset + 2U < BASE58CHECK_ADDRESS_SIZE); i++) {
        out[offset++] = hex[(address[i] >> 4) & 0x0FU];
        out[offset++] = hex[address[i] & 0x0FU];
    }
    if (truncate && (offset + 3U < BASE58CHECK_ADDRESS_SIZE)) {
        out[offset++] = '.';
        out[offset++] = '.';
        out[offset++] = '.';
    }
    out[offset] = '\0';
}

unsigned short print_amount(uint64_t amount, char *out, uint32_t outlen, uint8_t sun) {
    int written;

    if ((out == NULL) || (outlen == 0U)) {
        return 0U;
    }

    written = snprintf(out, outlen, "%llu.%0*u", (unsigned long long) amount, (int) sun, 0);
    if (written < 0) {
        out[0] = '\0';
        return 0U;
    }
    if ((uint32_t) written >= outlen) {
        out[outlen - 1U] = '\0';
        return (unsigned short) (outlen - 1U);
    }
    return (unsigned short) written;
}

void initTx(txContext_t *context, txContent_t *content) {
    if (context != NULL) {
        memset(context, 0, sizeof(*context));
        cx_sha256_init(&context->sha2);
        context->initialized = true;
    }
    if (content != NULL) {
        memset(content, 0, sizeof(*content));
    }
}

tokenDefinition_t *getKnownToken(txContent_t *context) {
    extraInfo_t *info;

    if (context == NULL) {
        return NULL;
    }

    info = get_asset_info_by_addr(context->contractAddress);
    if (info == NULL) {
        return NULL;
    }

    return &info->token;
}

static void fuzz_fill_finalize_token_lookups(tronPluginFinalize_t *finalize) {
    switch (g_plugin_behavior.token_lookup_mode & 0x03U) {
        case 0U:
            finalize->tokenLookup1 = NULL;
            finalize->tokenLookup2 = NULL;
            break;
        case 1U:
            finalize->tokenLookup1 = fuzz_lookup_known_1;
            finalize->tokenLookup2 = NULL;
            break;
        case 2U:
            finalize->tokenLookup1 = fuzz_lookup_unknown;
            finalize->tokenLookup2 = NULL;
            break;
        default:
            finalize->tokenLookup1 = fuzz_lookup_known_1;
            finalize->tokenLookup2 = fuzz_lookup_known_2;
            break;
    }
}

static void fuzz_handle_plugin_call(uintptr_t message, void *parameters) {
    switch ((tron_plugin_msg_t) message) {
        case TRON_PLUGIN_INIT_CONTRACT: {
            tronPluginInitContract_t *init = (tronPluginInitContract_t *) parameters;

            if ((g_plugin_behavior.init_mode & 0x80U) != 0U) {
                fuzz_throw_os_lib_exception(0x1101);
            }
            init->result = fuzz_decode_plugin_result(g_plugin_behavior.init_mode);
            return;
        }
        case TRON_PLUGIN_PROVIDE_PARAMETER: {
            tronPluginProvideParameter_t *provide = (tronPluginProvideParameter_t *) parameters;
            uint8_t result_mode = g_plugin_behavior.parameter_mode;

            if ((result_mode & 0x80U) != 0U) {
                fuzz_throw_os_lib_exception(0x1102);
            }
            if ((g_plugin_behavior.parameter_fail_cfg & 0x80U) != 0U) {
                const uint8_t fail_index = g_plugin_behavior.parameter_fail_cfg & 0x7FU;
                const uint32_t parameter_index =
                    (provide->parameterOffset >= SELECTOR_LENGTH)
                        ? (uint32_t) ((provide->parameterOffset - SELECTOR_LENGTH) / INT256_LENGTH)
                        : 0U;
                if (parameter_index == fail_index) {
                    result_mode = TRON_PLUGIN_RESULT_ERROR;
                }
            }
            provide->result = fuzz_decode_plugin_result(result_mode);
            return;
        }
        case TRON_PLUGIN_FINALIZE: {
            tronPluginFinalize_t *finalize = (tronPluginFinalize_t *) parameters;

            if ((g_plugin_behavior.finalize_mode & 0x80U) != 0U) {
                fuzz_throw_os_lib_exception(0x1103);
            }
            finalize->result = fuzz_decode_plugin_result(g_plugin_behavior.finalize_mode);
            finalize->uiType =
                ((g_plugin_behavior.ui_type_mode & 0x01U) != 0U) ? TRON_UI_TYPE_AMOUNT_ADDRESS
                                                                 : TRON_UI_TYPE_GENERIC;
            finalize->numScreens = g_plugin_behavior.num_screens;
            finalize->address = finalize->txContent->contractAddress;
            finalize->amount = finalize->txContent->TRC20Amount;
            fuzz_fill_finalize_token_lookups(finalize);
            return;
        }
        case TRON_PLUGIN_PROVIDE_INFO: {
            tronPluginProvideInfo_t *provide = (tronPluginProvideInfo_t *) parameters;

            if ((g_plugin_behavior.provide_info_mode & 0x80U) != 0U) {
                fuzz_throw_os_lib_exception(0x1104);
            }
            provide->result = fuzz_decode_plugin_result(g_plugin_behavior.provide_info_mode);
            provide->additionalScreens = g_plugin_behavior.additional_screens & 0x1FU;
            return;
        }
        case TRON_PLUGIN_QUERY_CONTRACT_ID: {
            tronQueryContractID_t *query = (tronQueryContractID_t *) parameters;

            if ((g_plugin_behavior.query_contract_id_mode & 0x80U) != 0U) {
                fuzz_throw_os_lib_exception(0x1105);
            }
            query->result = fuzz_decode_plugin_result(g_plugin_behavior.query_contract_id_mode);
            if (query->result == TRON_PLUGIN_RESULT_OK) {
                if (!g_plugin_behavior.empty_contract_name) {
                    snprintf(query->name, query->nameLength, "Plugin%u", (unsigned int) pluginType);
                } else if (query->nameLength > 0U) {
                    query->name[0] = '\0';
                }
                if (!g_plugin_behavior.empty_contract_version) {
                    snprintf(query->version,
                             query->versionLength,
                             "V%u",
                             (unsigned int) (query->txContent->customSelector & 0x0FU));
                } else if (query->versionLength > 0U) {
                    query->version[0] = '\0';
                }
            }
            return;
        }
        case TRON_PLUGIN_QUERY_CONTRACT_UI: {
            tronQueryContractUI_t *query = (tronQueryContractUI_t *) parameters;

            if ((g_plugin_behavior.query_contract_ui_mode & 0x80U) != 0U) {
                fuzz_throw_os_lib_exception(0x1106);
            }
            if (query->screenIndex == g_plugin_behavior.query_contract_ui_fail_index) {
                query->result = TRON_PLUGIN_RESULT_ERROR;
                return;
            }
            query->result = fuzz_decode_plugin_result(g_plugin_behavior.query_contract_ui_mode);
            if (query->result == TRON_PLUGIN_RESULT_OK) {
                snprintf(query->title, query->titleLength, "Field %u", (unsigned int) query->screenIndex);
                if (query->item1 != NULL) {
                    snprintf(query->msg,
                             query->msgLength,
                             "%s/%s",
                             query->network_ticker,
                             query->item1->token.ticker);
                } else {
                    snprintf(query->msg,
                             query->msgLength,
                             "sel:%08x",
                             (unsigned int) query->txContent->customSelector);
                }
            }
            return;
        }
        default:
            fuzz_throw_os_lib_exception(0x11FF);
    }
}

void os_lib_call(uintptr_t *params) {
    if (params == NULL) {
        fuzz_throw_os_lib_exception(0x10FF);
    }

    if (params[1] == TRON_PLUGIN_CHECK_PRESENCE) {
        if ((g_plugin_behavior.presence_mode & 0x01U) != 0U) {
            fuzz_throw_os_lib_exception(0x10FE);
        }
        return;
    }

    fuzz_handle_plugin_call(params[1], (void *) (uintptr_t) params[2]);
}
