#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "chain_config.h"
#include "ledger_pki.h"
#include "os_pki.h"

static uint32_t g_fuzz_challenge;
static check_signature_with_pki_status_t g_fuzz_pki_status;
static bool g_fuzz_cal_certificate;

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
