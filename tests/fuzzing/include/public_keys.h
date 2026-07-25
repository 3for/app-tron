#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "os_pki.h"

extern const uint8_t LEDGER_SIGNATURE_PUBLIC_KEY[65];
extern const uint8_t TRUSTED_NAME_PUB_KEY[65];

bool check_loaded_pki_certificate_name(const char *expected_name);

bool check_signature_with_pubkey(uint8_t *buffer,
                                 const uint8_t bufLen,
                                 const uint8_t *PubKey,
                                 const uint8_t keyLen,
                                 const uint8_t keyUsageExp,
                                 const uint8_t *signature,
                                 const uint8_t sigLen);
