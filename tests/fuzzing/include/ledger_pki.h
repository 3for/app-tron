#pragma once

#include <stdint.h>

#include "buffer.h"
#include "cx.h"

typedef enum {
    CHECK_SIGNATURE_WITH_PKI_SUCCESS = 0,
    CHECK_SIGNATURE_WITH_PKI_MISSING_CERTIFICATE,
    CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_USAGE,
    CHECK_SIGNATURE_WITH_PKI_WRONG_CERTIFICATE_CURVE,
    CHECK_SIGNATURE_WITH_PKI_WRONG_SIGNATURE,
} check_signature_with_pki_status_t;

check_signature_with_pki_status_t check_signature_with_pki(buffer_t hash,
                                                           const uint8_t *expected_key_usage,
                                                           const cx_curve_t *expected_curve,
                                                           buffer_t signature);
