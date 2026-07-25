#pragma once

#include <stddef.h>
#include <stdint.h>

#include "cx.h"

#define CERTIFICATE_PUBLIC_KEY_USAGE_TRUSTED_NAME 4
#define CERTIFICATE_PUBLIC_KEY_USAGE_COIN_META    8
#define CERTIFICATE_PUBLIC_KEY_USAGE_CALLDATA     11
#define CERTIFICATE_TRUSTED_NAME_MAXLEN            32

typedef cx_ecfp_public_key_t cx_ecfp_384_public_key_t;

int os_pki_get_info(uint8_t *key_usage,
                    uint8_t *trusted_name,
                    size_t *trusted_name_len,
                    cx_ecfp_384_public_key_t *public_key);
