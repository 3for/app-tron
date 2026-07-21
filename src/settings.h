#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "os.h"

#define N_storage (*(volatile internalStorage_t *) PIC(&N_storage_real))

// The settings, stored in NVRAM. Mirrors app-ethereum's internalStorage_t: a struct of
// named flags (rather than a flat bitfield), so each setting reads as N_storage.<field>.
// Keep the field order stable across upgrades; existing installations may retain this layout.
typedef struct internalStorage_t {
    bool dataAllowed;
    bool customContract;
    // Reserved slot for the removed truncate-address setting. Do not remove or reuse it.
    bool reservedTruncateAddress;
    bool signByHash;
    bool verbose_tip712;
    // Always display the transaction hash in the review (app-ethereum's displayHash).
    bool displayHash;
#ifdef HAVE_GATING_SUPPORT
    // Gated-signing throttle counter (see provide_gating). app-ethereum keeps this in the
    // same N_storage struct (N_storage.gating_counter), so TRON does too.
    uint8_t gating_counter;
#endif  // HAVE_GATING_SUPPORT
    bool initialized;
} internalStorage_t;

// the settings, stored in NVRAM. Initializer is ignored by ledger.
extern const internalStorage_t N_storage_real;
