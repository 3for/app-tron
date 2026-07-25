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
#include "common_712.h"  // e_tip712_filtering_mode, ui_712_start prototype
#include "tip712_fuzz_support.h"

tmpCtx_t tmpCtx;
txContent_t txContent;
txContext_t txContext;
uint8_t appState;
uint16_t apdu_response_code;
cx_sha3_t global_sha3;
strings_t strings;
internalStorage_t g_fuzz_storage;
const internalStorage_t N_storage_real = {0};
uint8_t perm_field_count;
const char *perm_field_items[PERM_MAX_FIELDS];
char (*perm_field_labels)[PERM_ITEM_LEN];
char (*perm_field_values)[PERM_VAL_LEN];
uint8_t votes_count;
char *vote_display_buffer;
volatile uint8_t customContractField;
uint8_t G_io_apdu_buffer[260];

void fuzz_set_settings(uint8_t bits) {
    g_fuzz_storage.dataAllowed = (bits >> S_DATA_ALLOWED) & 1U;
    g_fuzz_storage.customContract = (bits >> S_CUSTOM_CONTRACT) & 1U;
    g_fuzz_storage.reservedTruncateAddress =
        (bits >> S_RESERVED_TRUNCATE_ADDRESS) & 1U;
    g_fuzz_storage.signByHash = (bits >> S_SIGN_BY_HASH) & 1U;
    g_fuzz_storage.verbose_tip712 = (bits >> S_VERBOSE_TIP712) & 1U;
    g_fuzz_storage.displayHash = (bits >> S_DISPLAY_HASH) & 1U;
}
const uint8_t LEDGER_SIGNATURE_PUBLIC_KEY[65] = {0};
bool g_fuzz_signature_valid = true;

enum {
    FUZZ_ENV_BAD_SIGNATURE = 1U << 0,
    FUZZ_ENV_FAIL_UI_START = 1U << 1,
    FUZZ_ENV_FAIL_UI_SIGN = 1U << 2,
    FUZZ_ENV_FAIL_UI_APPROVE = 1U << 3,
    FUZZ_ENV_FAIL_UI_REJECT = 1U << 4,
    FUZZ_ENV_DISABLE_TRUSTED_NAME = 1U << 5,
};

static uint8_t g_fuzz_environment;
static tip712_fuzz_ui_stats_t g_fuzz_ui_stats;

static extraInfo_t fuzz_assets[MAX_ASSETS];
static chain_config_t fuzz_chain_config = {.chainId = 0x44U};
static s_trusted_name g_fuzz_trusted_name;

__attribute__((weak)) void fuzz_reset_extra_context(void) {}

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
    memset(tmpCtx.transactionContext.assetKind, 0, sizeof(tmpCtx.transactionContext.assetKind));
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
        tmpCtx.transactionContext.assetKind[i] = ASSET_KIND_TOKEN;
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
    fuzz_reset_extra_context();
    memset(&tmpCtx, 0, sizeof(tmpCtx));
    memset(&txContent, 0, sizeof(txContent));
    memset(&txContext, 0, sizeof(txContext));
    memset(&strings, 0, sizeof(strings));
    memset(&g_fuzz_trusted_name, 0, sizeof(g_fuzz_trusted_name));
    appState = APP_STATE_IDLE;
    seed_default_assets();
}

void init_tip712_fuzz_environment(void) {
    reset_app_context();
    apdu_response_code = SWO_SUCCESS;
    fuzz_set_settings(0);
    fuzz_set_tip712_environment(0);
    memset(&g_fuzz_ui_stats, 0, sizeof(g_fuzz_ui_stats));
    memset(&global_sha3, 0, sizeof(global_sha3));
}

void fuzz_set_tip712_environment(uint8_t bits) {
    g_fuzz_environment = bits;
    g_fuzz_signature_valid = (bits & FUZZ_ENV_BAD_SIGNATURE) == 0U;
}

tip712_fuzz_ui_stats_t fuzz_get_tip712_ui_stats(void) {
    return g_fuzz_ui_stats;
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

void ui_idle(void) {
    g_fuzz_ui_stats.idles++;
}

uint16_t ui_712_start(e_tip712_filtering_mode filtering) {
    (void) filtering;
    g_fuzz_ui_stats.starts++;
    return (g_fuzz_environment & FUZZ_ENV_FAIL_UI_START) != 0U ? SWO_INCORRECT_DATA
                                                               : SWO_SUCCESS;
}

void ui_712_switch_to_message(void) {}

void ui_712_start_unfiltered(void) {}

void ui_712_switch_to_sign(void) {}

void ui_error_blind_signing(void) {
    g_fuzz_ui_stats.blind_signing_errors++;
}

// NBGL review entry points are stubbed: the host fuzz build exercises parsing
// and state-machine logic, not the device UI. Approvals report success so the
// signing path proceeds.
uint16_t ui_sign_712(e_tip712_filtering_mode filtering) {
    (void) filtering;
    g_fuzz_ui_stats.signs++;
    return (g_fuzz_environment & FUZZ_ENV_FAIL_UI_SIGN) != 0U ? SWO_INCORRECT_DATA
                                                              : SWO_SUCCESS;
}

void tip712_format_hash(uint8_t index, const char **item, const char **value) {
    static const char domain_hash[] = "00";
    static const char message_hash[] = "00";

    if ((item == NULL) || (value == NULL)) {
        return;
    }
    switch (index) {
        case 0:
            *item = "Domain hash";
            *value = domain_hash;
            break;
        case 1:
            *item = "Message hash";
            *value = message_hash;
            break;
        default:
            *item = NULL;
            *value = NULL;
            break;
    }
}

bool ui_712_approve_cb(bool display_menu) {
    (void) display_menu;
    g_fuzz_ui_stats.approves++;
    return (g_fuzz_environment & FUZZ_ENV_FAIL_UI_APPROVE) == 0U;
}

bool ui_712_reject_cb(bool display_menu) {
    (void) display_menu;
    g_fuzz_ui_stats.rejects++;
    return (g_fuzz_environment & FUZZ_ENV_FAIL_UI_REJECT) == 0U;
}

bool ui_gcs(void) {
    return true;
}

void ui_gcs_cleanup(void) {}

// Challenge helpers (the real cmd_get_challenge.c pulls in device I/O, so the
// host build stubs just the value logic the GCS/proxy paths use).
static uint32_t g_fuzz_challenge = 0;

void roll_challenge(void) {
    g_fuzz_challenge += 1;
}

uint32_t get_challenge(void) {
    return g_fuzz_challenge;
}

bool check_challenge(uint32_t received_challenge) {
    return received_challenge == g_fuzz_challenge;
}

bool ux_flow_display(ui_approval_state_t state, bool warning) {
    (void) state;
    (void) warning;
    return true;
}

void ui_review_menu_cleanup(void) {}

bool ui_callback_tx_ok(bool display_menu) {
    (void) display_menu;
    return true;
}

void ui_error_custom_contract(void) {}

bool ui_callback_signMessage712_v0_ok(bool display_menu) {
    (void) display_menu;
    return true;
}

bool ui_callback_signMessage712_v0_cancel(bool display_menu) {
    (void) display_menu;
    return true;
}

__attribute__((weak)) void forget_known_assets(void) {
    seed_default_assets();
}

__attribute__((weak)) bool asset_slot_is_kind(uint8_t index, asset_kind_t kind) {
    return (index < MAX_ASSETS) && tmpCtx.transactionContext.assetSet[index] &&
           (tmpCtx.transactionContext.assetKind[index] == kind);
}

__attribute__((weak)) int get_token_index_by_addr(const uint8_t *addr) {
    for (size_t i = 0; i < MAX_ASSETS; i++) {
        if (asset_slot_is_kind(i, ASSET_KIND_TOKEN) &&
            (memcmp(fuzz_assets[i].token.address, addr, ADDRESS_LENGTH) == 0)) {
            return (int) i;
        }
    }
    return -1;
}

__attribute__((weak)) const tokenDefinition_t *get_token_info_by_addr(const uint8_t *addr) {
    int idx = get_token_index_by_addr(addr);

    return (idx >= 0) ? &fuzz_assets[idx].token : NULL;
}

#ifndef TARGET_NANOS
__attribute__((weak)) const nftInfo_t *get_nft_info_by_addr(const uint8_t *addr) {
    (void) addr;
    return NULL;
}
#endif

__attribute__((weak)) int commit_current_asset_info(asset_kind_t kind,
                                                    const extraInfo_t *candidate) {
    uint8_t idx = tmpCtx.transactionContext.currentAssetIndex;

    if ((idx >= MAX_ASSETS) || (candidate == NULL)) {
        return -1;
    }
    memcpy(&fuzz_assets[idx], candidate, sizeof(*candidate));
    memcpy(&tmpCtx.transactionContext.extraInfo[idx], candidate, sizeof(*candidate));
    tmpCtx.transactionContext.assetSet[idx] = true;
    tmpCtx.transactionContext.assetKind[idx] = kind;
    tmpCtx.transactionContext.currentAssetIndex = (idx + 1U) % MAX_ASSETS;
    return idx;
}

bool check_signature_with_pubkey(uint8_t *buffer,
                                 const uint8_t bufLen,
                                 const uint8_t *PubKey,
                                 const uint8_t keyLen,
                                 const uint8_t keyUsageExp,
                                 const uint8_t *signature,
                                 const uint8_t sigLen) {
    (void) buffer;
    (void) bufLen;
    (void) PubKey;
    (void) keyLen;
    (void) keyUsageExp;
    (void) signature;
    (void) sigLen;
    return g_fuzz_signature_valid;
}

const s_trusted_name *get_trusted_name(uint8_t type_count,
                                       const e_name_type *types,
                                       uint8_t source_count,
                                       const e_name_source *sources,
                                       const uint64_t *chain_id,
                                       const uint8_t *addr) {
    if ((g_fuzz_environment & FUZZ_ENV_DISABLE_TRUSTED_NAME) != 0U ||
        (type_count == 0U) || (types == NULL) || (source_count == 0U) || (sources == NULL) ||
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

// NOTE: array_bytes_string, amountToString, getEthDisplayableAddress,
// ethToTronBase58, u64_from_BE, allzeroes and ismaxint are provided by the real
// src/tron-sdk/common_utils.c, which is compiled into this fuzzer.
