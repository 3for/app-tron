#pragma once

#include <stdint.h>
#include <stdbool.h>

// Fuzzing stub for src/settings.h: mirrors the app's internalStorage_t struct so the
// code under test reads N_storage.<field>, but backs it with a plain (writable) global
// the harness controls instead of NVRAM.
typedef struct internalStorage_t {
    bool dataAllowed;
    bool customContract;
    bool truncateAddress;
    bool signByHash;
    bool verbose_tip712;
    bool displayHash;
#ifdef HAVE_GATING_SUPPORT
    uint8_t gating_counter;
#endif  // HAVE_GATING_SUPPORT
    bool initialized;
} internalStorage_t;

extern internalStorage_t g_fuzz_storage;
extern const internalStorage_t N_storage_real;

#define N_storage g_fuzz_storage

// Settings-byte bit layout (the GET_APP_CONFIGURATION wire bits). The fuzz drivers seed
// N_storage from a single fuzzed byte through fuzz_set_settings().
#define S_DATA_ALLOWED     0
#define S_CUSTOM_CONTRACT  1
#define S_TRUNCATE_ADDRESS 2
#define S_SIGN_BY_HASH     3
#define S_VERBOSE_TIP712   4
#define S_DISPLAY_HASH     5

void fuzz_set_settings(uint8_t bits);
