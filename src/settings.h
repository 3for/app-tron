#pragma once

#include <stdint.h>

#include "os.h"

typedef uint8_t internal_storage_t;

#define N_settings (*(volatile internal_storage_t *) PIC(&N_storage_real))

// the settings, stored in NVRAM. Initializer is ignored by ledger.
extern const internal_storage_t N_storage_real;

#ifdef HAVE_GATING_SUPPORT
// Gated-signing throttle counter, stored in NVRAM. app-ethereum keeps this in the
// N_storage struct (N_storage.gating_counter); TRON's settings are a flat bitfield,
// so it lives in its own NVRAM byte instead.
extern const uint8_t N_gating_counter_real;
#define N_gating_counter (*(volatile uint8_t *) PIC(&N_gating_counter_real))
#endif  // HAVE_GATING_SUPPORT

// flip a bit k = 0 to 7 for u8
#define _FLIP_BIT(n, k) (((n) ^ (1 << (k))))

// toggle a setting item
#define SETTING_TOGGLE(_set)                                                                   \
    do {                                                                                       \
        internal_storage_t _temp_settings = _FLIP_BIT(N_settings, _set);                       \
        nvm_write((void *) &N_settings, (void *) &_temp_settings, sizeof(internal_storage_t)); \
    } while (0)

// check a setting item
#define HAS_SETTING(k) ((N_settings & (1 << (k))) >> (k))

#define S_DATA_ALLOWED     0
#define S_CUSTOM_CONTRACT  1
#define S_TRUNCATE_ADDRESS 2
#define S_SIGN_BY_HASH     3
#define S_VERBOSE_TIP712   4

#define S_INITIALIZED 7
