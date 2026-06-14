#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "app_errors.h"
#include "common_utils.h"
#include "cx.h"
#include "helpers.h"
#include "parse.h"
#include "public_keys.h"
#include "settings.h"
#include "trusted_name.h"
#include "ui_idle_menu.h"
#include "ui_globals.h"
#include "ui_review_menu.h"

tmpCtx_t tmpCtx;
txContent_t txContent;
txContext_t txContext;
dataContext_t dataContext;
pluginType_t pluginType;
uint8_t appState;
uint16_t apdu_response_code;
cx_sha3_t global_sha3;
strings_t strings;
internalStorage_t g_fuzz_storage;
const internalStorage_t N_storage_real = {0};

void fuzz_set_settings(uint8_t bits) {
    g_fuzz_storage.dataAllowed = (bits >> S_DATA_ALLOWED) & 1U;
    g_fuzz_storage.customContract = (bits >> S_CUSTOM_CONTRACT) & 1U;
    g_fuzz_storage.truncateAddress = (bits >> S_TRUNCATE_ADDRESS) & 1U;
    g_fuzz_storage.signByHash = (bits >> S_SIGN_BY_HASH) & 1U;
    g_fuzz_storage.verbose_tip712 = (bits >> S_VERBOSE_TIP712) & 1U;
}
const uint8_t LEDGER_SIGNATURE_PUBLIC_KEY[65] = {0};
bool g_fuzz_signature_valid = true;

static extraInfo_t fuzz_assets[MAX_ASSETS];
static chain_config_t fuzz_chain_config = {.chainId = 0x44U};
static s_trusted_name g_fuzz_trusted_name;

static void seed_default_assets(void) {
    static const uint8_t token_addrs[][ADDRESS_LENGTH] = {
        {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
         0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
        {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
         0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
        {0xC1, 0x83, 0x60, 0x21, 0x7D, 0x8F, 0x7A, 0xB5, 0xE7, 0xC5,
         0x16, 0x56, 0x67, 0x61, 0xEA, 0x12, 0xCE, 0x7F, 0x9D, 0x72},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    };
    static const char *const tickers[] = {"TOK11", "TOK22", "ENS", "ZERO"};
    static const uint8_t decimals[] = {18U, 6U, 18U, 0U};

    memset(tmpCtx.transactionContext.extraInfo, 0, sizeof(tmpCtx.transactionContext.extraInfo));
    memset(tmpCtx.transactionContext.assetSet, 0, sizeof(tmpCtx.transactionContext.assetSet));
    tmpCtx.transactionContext.currentAssetIndex = 0;
    memset(fuzz_assets, 0, sizeof(fuzz_assets));

    for (size_t i = 0; i < ARRAY_SIZE(token_addrs); i++) {
        memcpy(fuzz_assets[i].token.address, token_addrs[i], sizeof(token_addrs[i]));
        memcpy(tmpCtx.transactionContext.extraInfo[i].token.address,
               token_addrs[i],
               sizeof(token_addrs[i]));
        memcpy(fuzz_assets[i].token.ticker, tickers[i], strlen(tickers[i]) + 1U);
        memcpy(tmpCtx.transactionContext.extraInfo[i].token.ticker,
               tickers[i],
               strlen(tickers[i]) + 1U);
        fuzz_assets[i].token.decimals = decimals[i];
        tmpCtx.transactionContext.extraInfo[i].token.decimals = decimals[i];
        tmpCtx.transactionContext.assetSet[i] = true;
    }
}

const chain_config_t *chainConfig = &fuzz_chain_config;

static size_t fuzz_support_bounded_strlen(const char *src, size_t max_len) {
    if (src == NULL) {
        return 0U;
    }
    return strnlen(src, max_len);
}

static char fuzz_support_hex_digit(uint8_t value) {
    static const char hex[] = "0123456789ABCDEF";

    return hex[value & 0x0FU];
}

static bool fuzz_support_append_string(char *dst,
                                       size_t dst_size,
                                       const char *src,
                                       size_t src_max_len) {
    size_t dst_len;
    size_t src_len;
    size_t copy_len;

    if ((dst == NULL) || (src == NULL) || (dst_size == 0U)) {
        return false;
    }

    dst_len = strnlen(dst, dst_size);
    if (dst_len >= dst_size) {
        return false;
    }
    src_len = fuzz_support_bounded_strlen(src, src_max_len);
    copy_len = MIN(dst_size - dst_len - 1U, src_len);
    memcpy(dst + dst_len, src, copy_len);
    dst[dst_len + copy_len] = '\0';
    return copy_len == src_len;
}

void reset_app_context(void) {
    memset(&tmpCtx, 0, sizeof(tmpCtx));
    memset(&txContent, 0, sizeof(txContent));
    memset(&txContext, 0, sizeof(txContext));
    memset(&dataContext, 0, sizeof(dataContext));
    memset(&strings, 0, sizeof(strings));
    memset(&g_fuzz_trusted_name, 0, sizeof(g_fuzz_trusted_name));
    apdu_response_code = SWO_SUCCESS;
    appState = APP_STATE_IDLE;
    pluginType = PLUGIN_TYPE_NONE;
    seed_default_assets();
}

void init_tip712_fuzz_environment(void) {
    reset_app_context();
    fuzz_set_settings(0);
    memset(&global_sha3, 0, sizeof(global_sha3));
}

uint16_t io_seproxyhal_send_status(uint16_t sw, uint32_t tx, bool reset, bool idle) {
    (void) tx;
    (void) idle;
    apdu_response_code = sw;
    if (reset) {
        reset_app_context();
    }
    return sw;
}

int io_send_sw(uint16_t sw) {
    apdu_response_code = sw;
    return sw;
}

void ui_idle(void) {}

void ui_712_start(void) {}

void ui_712_switch_to_message(void) {}

void ui_712_start_unfiltered(void) {}

void ui_712_switch_to_sign(void) {}

void ui_error_blind_signing(void) {}

void ux_flow_display(ui_approval_state_t state, bool warning) {
    (void) state;
    (void) warning;
}

bool ui_callback_signMessage712_v0_ok(bool display_menu) {
    (void) display_menu;
    return true;
}

bool ui_callback_signMessage712_v0_cancel(bool display_menu) {
    (void) display_menu;
    return true;
}

void forget_known_assets(void) {
    seed_default_assets();
}

extraInfo_t *get_current_asset_info(void) {
    uint8_t idx = tmpCtx.transactionContext.currentAssetIndex;

    if (idx >= MAX_ASSETS) {
        return NULL;
    }
    return &fuzz_assets[idx];
}

int get_asset_index_by_addr(const uint8_t *addr) {
    for (size_t i = 0; i < MAX_ASSETS; i++) {
        if (memcmp(fuzz_assets[i].token.address, addr, ADDRESS_LENGTH) == 0) {
            return (int) i;
        }
    }
    return -1;
}

extraInfo_t *get_asset_info_by_addr(const uint8_t *addr) {
    int idx = get_asset_index_by_addr(addr);

    return (idx >= 0) ? &fuzz_assets[idx] : NULL;
}

void validate_current_asset_info(void) {}

int check_signature_with_pubkey(const char *tag,
                                uint8_t *buffer,
                                const uint8_t bufLen,
                                const uint8_t *PubKey,
                                const uint8_t keyLen,
                                const uint8_t keyUsageExp,
                                uint8_t *signature,
                                const uint8_t sigLen) {
    (void) tag;
    (void) buffer;
    (void) bufLen;
    (void) PubKey;
    (void) keyLen;
    (void) keyUsageExp;
    (void) signature;
    (void) sigLen;
    return g_fuzz_signature_valid ? CX_OK : CX_INTERNAL_ERROR;
}

const s_trusted_name *get_trusted_name(uint8_t type_count,
                                       const e_name_type *types,
                                       uint8_t source_count,
                                       const e_name_source *sources,
                                       const uint64_t *chain_id,
                                       const uint8_t *addr) {
    if ((type_count == 0U) || (types == NULL) || (source_count == 0U) || (sources == NULL) ||
        (chain_id == NULL) || (addr == NULL) || allzeroes(addr, ADDRESS_LENGTH)) {
        return NULL;
    }

    if (sizeof(g_fuzz_trusted_name.name) < sizeof("TN-0000-00")) {
        return NULL;
    }

    g_fuzz_trusted_name.name[0] = 'T';
    g_fuzz_trusted_name.name[1] = 'N';
    g_fuzz_trusted_name.name[2] = '-';
    g_fuzz_trusted_name.name[3] = fuzz_support_hex_digit(addr[ADDRESS_LENGTH - 3U] >> 4);
    g_fuzz_trusted_name.name[4] = fuzz_support_hex_digit(addr[ADDRESS_LENGTH - 3U]);
    g_fuzz_trusted_name.name[5] = fuzz_support_hex_digit(addr[ADDRESS_LENGTH - 2U] >> 4);
    g_fuzz_trusted_name.name[6] = fuzz_support_hex_digit(addr[ADDRESS_LENGTH - 2U]);
    g_fuzz_trusted_name.name[7] = '-';
    g_fuzz_trusted_name.name[8] = fuzz_support_hex_digit(addr[ADDRESS_LENGTH - 1U] >> 4);
    g_fuzz_trusted_name.name[9] = fuzz_support_hex_digit(addr[ADDRESS_LENGTH - 1U]);
    g_fuzz_trusted_name.name[10] = '\0';
    return &g_fuzz_trusted_name;
}

bool has_trusted_name(void) {
    return g_fuzz_trusted_name.name[0] != '\0';
}

int array_bytes_string(char *out, size_t outl, const void *value, size_t len) {
    const uint8_t *bytes = (const uint8_t *) value;
    static const char hex[] = "0123456789abcdef";

    if (outl < (len * 2U + 3U)) {
        if (outl > 0U) {
            out[0] = '\0';
        }
        return -1;
    }

    out[0] = '0';
    out[1] = 'x';
    for (size_t i = 0; i < len; i++) {
        out[2U + 2U * i] = hex[(bytes[i] >> 4) & 0x0FU];
        out[2U + 2U * i + 1U] = hex[bytes[i] & 0x0FU];
    }
    out[2U + len * 2U] = '\0';
    return 0;
}

bool amountToString(const uint8_t *amount,
                    uint8_t amount_len,
                    uint8_t decimals,
                    const char *ticker,
                    char *out_buffer,
                    size_t out_buffer_size) {
    (void) decimals;
    if ((out_buffer == NULL) || (out_buffer_size == 0U)) {
        return false;
    }

    if (array_bytes_string(out_buffer, out_buffer_size, amount, amount_len) < 0) {
        return false;
    }

    if ((ticker != NULL) && (ticker[0] != '\0')) {
        const size_t used = strnlen(out_buffer, out_buffer_size);
        const size_t left = (used < out_buffer_size) ? (out_buffer_size - used) : 0U;
        if ((left < 2U) ||
            !fuzz_support_append_string(out_buffer, out_buffer_size, " ", sizeof(" ") - 1U) ||
            !fuzz_support_append_string(out_buffer, out_buffer_size, ticker, MAX_TICKER_LEN)) {
            return false;
        }
    }

    return true;
}

bool getEthDisplayableAddress(const uint8_t *in, char *out, size_t out_len, uint64_t chainId) {
    (void) chainId;
    return array_bytes_string(out, out_len, in, ADDRESS_LENGTH) == 0;
}

bool ethToTronBase58(const char *ethAddress, char *out58, size_t out58_len) {
    if ((ethAddress == NULL) || (out58 == NULL) || (out58_len < 2U)) {
        return false;
    }
    out58[0] = '\0';
    return fuzz_support_append_string(out58, out58_len, "T", sizeof("T") - 1U) &&
           fuzz_support_append_string(out58, out58_len, ethAddress, 42U);
}

uint64_t u64_from_BE(const uint8_t *in, uint8_t size) {
    uint64_t value = 0;
    for (uint8_t i = 0; (i < size) && (i < sizeof(value)); i++) {
        value = (value << 8) | in[i];
    }
    return value;
}

int allzeroes(const void *buf, size_t n) {
    const uint8_t *bytes = (const uint8_t *) buf;
    for (size_t i = 0; i < n; i++) {
        if (bytes[i] != 0U) {
            return 0;
        }
    }
    return 1;
}

int ismaxint(const uint8_t *buf, int n) {
    for (int i = 0; i < n; i++) {
        if (buf[i] != 0xFFU) {
            return 0;
        }
    }
    return 1;
}
