#pragma once

// Host-side mock of the SDK <crypto_helpers.h>. The GCS get_public_key helper
// derives a public key for descriptor verification; in the fuzz build there is
// no secure element, so this returns a deterministic dummy key and success.

#include <stddef.h>
#include <stdint.h>

#include "cx.h"

static inline cx_err_t bip32_derive_get_pubkey_256(cx_curve_t curve,
                                                   const uint32_t *path,
                                                   size_t path_len,
                                                   uint8_t raw_pubkey[65],
                                                   uint8_t *chain_code,
                                                   cx_md_t hashID) {
    (void) curve;
    (void) path;
    (void) path_len;
    (void) hashID;
    if (raw_pubkey != NULL) {
        memset(raw_pubkey, 0, 65);
        raw_pubkey[0] = 0x04;  // uncompressed point prefix
    }
    if (chain_code != NULL) {
        memset(chain_code, 0, 32);
    }
    return CX_OK;
}
