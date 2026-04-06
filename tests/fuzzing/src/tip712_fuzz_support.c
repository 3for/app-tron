#include <stdbool.h>
#include <stddef.h>
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

tmpCtx_t tmpCtx;
txContent_t txContent;
txContext_t txContext;
dataContext_t dataContext;
pluginType_t pluginType;
uint8_t appState;
uint16_t apdu_response_code;
cx_sha3_t global_sha3;
strings_t strings;
internal_storage_t g_fuzz_settings;
const internal_storage_t N_storage_real = 0;
char g_trusted_name[TRUSTED_NAME_MAX_LENGTH + 1];
const uint8_t LEDGER_SIGNATURE_PUBLIC_KEY[65] = {0};

static extraInfo_t fuzz_assets[MAX_ASSETS];
static chain_config_t fuzz_chain_config = {.chainId = 0x44U};

const chain_config_t *chainConfig = &fuzz_chain_config;

void reset_app_context(void) {
    memset(&tmpCtx, 0, sizeof(tmpCtx));
    memset(&txContent, 0, sizeof(txContent));
    memset(&txContext, 0, sizeof(txContext));
    memset(&dataContext, 0, sizeof(dataContext));
    memset(&strings, 0, sizeof(strings));
    memset(fuzz_assets, 0, sizeof(fuzz_assets));
    memset(g_trusted_name, 0, sizeof(g_trusted_name));
    apdu_response_code = APDU_RESPONSE_OK;
    appState = APP_STATE_IDLE;
    pluginType = PLUGIN_TYPE_NONE;
}

void init_tip712_fuzz_environment(void) {
    reset_app_context();
    g_fuzz_settings = 0;
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

void ui_idle(void) {}

void ui_712_start(void) {}

void ui_712_switch_to_message(void) {}

void ui_712_start_unfiltered(void) {}

void ui_712_switch_to_sign(void) {}

void ui_error_blind_signing(void) {}

bool ui_callback_signMessage712_v0_ok(bool display_menu) {
    (void) display_menu;
    return true;
}

bool ui_callback_signMessage712_v0_cancel(bool display_menu) {
    (void) display_menu;
    return true;
}

void forget_known_assets(void) {
    memset(fuzz_assets, 0, sizeof(fuzz_assets));
    memset(tmpCtx.transactionContext.assetSet, 0, sizeof(tmpCtx.transactionContext.assetSet));
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
        if (memcmp(fuzz_assets[i].token.address, addr, TRON_ADDRESS_SIZE) == 0) {
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

off_t read_bip32_path_712(const uint8_t *buffer,
                          uint16_t length,
                          messageSigningContext712_t *ctx_712) {
    if ((buffer == NULL) || (ctx_712 == NULL) || (length < 1U)) {
        return -1;
    }

    const uint8_t path_length = buffer[0];
    if ((path_length == 0U) || (path_length > MAX_BIP32_PATH) ||
        (length < (uint16_t) (1U + path_length * 4U))) {
        return -1;
    }

    memset(ctx_712, 0, sizeof(*ctx_712));
    ctx_712->pathLength = path_length;
    for (uint8_t i = 0; i < path_length; i++) {
        const uint8_t *entry = buffer + 1U + (size_t) i * 4U;
        ctx_712->bip32Path[i] =
            ((uint32_t) entry[0] << 24) | ((uint32_t) entry[1] << 16) |
            ((uint32_t) entry[2] << 8) | (uint32_t) entry[3];
    }
    return (off_t) (1U + path_length * 4U);
}

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
    return CX_OK;
}

const char *get_trusted_name(uint8_t type_count,
                             const e_name_type *types,
                             uint8_t source_count,
                             const e_name_source *sources,
                             const uint64_t *chain_id,
                             const uint8_t *addr) {
    (void) type_count;
    (void) types;
    (void) source_count;
    (void) sources;
    (void) chain_id;
    (void) addr;
    return NULL;
}

bool has_trusted_name(void) {
    return g_trusted_name[0] != '\0';
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
        const size_t used = strlen(out_buffer);
        const size_t left = (used < out_buffer_size) ? (out_buffer_size - used) : 0U;
        if ((left < 2U) || (strlcat(out_buffer, " ", out_buffer_size) >= out_buffer_size) ||
            (strlcat(out_buffer, ticker, out_buffer_size) >= out_buffer_size)) {
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
    strlcpy(out58, "T", out58_len);
    strlcat(out58, ethAddress, out58_len);
    return true;
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
