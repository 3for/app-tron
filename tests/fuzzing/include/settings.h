#pragma once

#include <stdint.h>

typedef uint8_t internal_storage_t;

extern internal_storage_t g_fuzz_settings;
extern const internal_storage_t N_storage_real;

#define HAS_SETTING(k) ((g_fuzz_settings >> (k)) & 0x01U)

#define S_DATA_ALLOWED     0
#define S_CUSTOM_CONTRACT  1
#define S_TRUNCATE_ADDRESS 2
#define S_SIGN_BY_HASH     3
#define S_VERBOSE_TIP712   4
#define S_INITIALIZED      7
