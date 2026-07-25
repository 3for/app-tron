#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "chain_config.h"
#include "ledger_pki.h"
#include "os_pki.h"
#include "parse.h"
#include "app_errors.h"
#include "ui_globals.h"

static uint32_t g_fuzz_challenge;
static check_signature_with_pki_status_t g_fuzz_pki_status;
static bool g_fuzz_cal_certificate;
static chain_config_t g_fuzz_chain_config = {.chainId = TRON_MAINNET_CHAINID};

tmpCtx_t tmpCtx;
const chain_config_t *chainConfig = &g_fuzz_chain_config;
uint8_t G_io_apdu_buffer[260];
const uint8_t LEDGER_SIGNATURE_PUBLIC_KEY[65] = {0};
const uint8_t LEDGER_NFT_METADATA_PUBLIC_KEY[65] = {0};

void fuzz_external_metadata_set_certificate_status(uint8_t control) {
    g_fuzz_cal_certificate = (control & 0x80U) != 0U;
    switch ((control & 0x7fU) % 6U) {
        case 0:
            g_fuzz_pki_status = CHECK_SIGNATURE_WITH_PKI_SUCCESS;
            break;
        case 1:
            g_fuzz_pki_status = CHECK_SIGNATURE_WITH_PKI_MISSING_CERTIFICATE;
            break;
        case 2:
            g_fuzz_pki_status = CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_USAGE;
            break;
        case 3:
            g_fuzz_pki_status = CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_CURVE;
            break;
        case 4:
            g_fuzz_pki_status = CHECK_SIGNATURE_WITH_PKI_WRONG_SIGNATURE;
            break;
        default:
            /* Exercise ledger_pki.c's default/error branch as well. */
            g_fuzz_pki_status = (check_signature_with_pki_status_t) 0xff;
            break;
    }
    g_fuzz_challenge = 0U;
}

int os_pki_get_info(uint8_t *key_usage,
                    uint8_t *trusted_name,
                    size_t *trusted_name_len,
                    cx_ecfp_384_public_key_t *public_key) {
    const char *name = g_fuzz_cal_certificate ? "Trusted_Name_CAL" : "Trusted_Name";
    size_t name_len = strlen(name);

    (void) public_key;
    *key_usage = CERTIFICATE_PUBLIC_KEY_USAGE_TRUSTED_NAME;
    memcpy(trusted_name, name, name_len);
    *trusted_name_len = name_len;
    return 0;
}

check_signature_with_pki_status_t check_signature_with_pki(
    buffer_t hash,
    const uint8_t *expected_key_usage,
    const cx_curve_t *expected_curve,
    buffer_t signature) {
    (void) hash;
    (void) expected_key_usage;
    (void) expected_curve;
    (void) signature;
    return g_fuzz_pki_status;
}

void roll_challenge(void) {
    g_fuzz_challenge += 1U;
}

uint32_t get_challenge(void) {
    return g_fuzz_challenge;
}

bool check_challenge(uint32_t received_challenge) {
    return received_challenge == g_fuzz_challenge;
}

bool chain_is_ethereum_compatible(const uint64_t *chain_id) {
    return (chain_id != NULL) &&
           ((*chain_id == TRON_MAINNET_CHAINID) || (*chain_id == TRON_NILE_CHAINID));
}

bool app_compatible_with_chain_id(const uint64_t *chain_id) {
    return (chain_id != NULL) && (*chain_id == chainConfig->chainId);
}

int io_send_sw(uint16_t sw) {
    return sw;
}

int io_send_response_pointer(const uint8_t *buffer, uint16_t tx, uint16_t sw) {
    (void) buffer;
    (void) tx;
    return sw;
}

void fuzz_external_metadata_reset_assets(void) {
    memset(&tmpCtx.transactionContext, 0, sizeof(tmpCtx.transactionContext));
}

bool asset_slot_is_kind(uint8_t index, asset_kind_t kind) {
    return (index < MAX_ASSETS) && tmpCtx.transactionContext.assetSet[index] &&
           (tmpCtx.transactionContext.assetKind[index] == kind);
}

int commit_current_asset_info(asset_kind_t kind, const extraInfo_t *candidate) {
    uint8_t index = tmpCtx.transactionContext.currentAssetIndex;

    if ((candidate == NULL) || (index >= MAX_ASSETS)) {
        return -1;
    }
    memcpy(&tmpCtx.transactionContext.extraInfo[index], candidate, sizeof(*candidate));
    tmpCtx.transactionContext.assetSet[index] = true;
    tmpCtx.transactionContext.assetKind[index] = kind;
    tmpCtx.transactionContext.currentAssetIndex = (index + 1U) % MAX_ASSETS;
    return index;
}
