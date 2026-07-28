#pragma once

// Host-side mock of the SDK <crypto_helpers.h>. The GCS get_public_key helper
// derives a public key for descriptor verification; in the fuzz build there is
// no secure element, so this returns a deterministic path-dependent dummy key.

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
    (void) hashID;
    if ((raw_pubkey == NULL) || (path == NULL) || (path_len == 0U) ||
        (path_len > 10U)) {
        return CX_INTERNAL_ERROR;
    }
    memset(raw_pubkey, 0, 65);
    raw_pubkey[0] = 0x04;  // uncompressed point prefix
    for (size_t i = 0; i < path_len; ++i) {
        const size_t offset = 1U + (i * sizeof(uint32_t));

        raw_pubkey[offset] = (uint8_t) (path[i] >> 24U);
        raw_pubkey[offset + 1U] = (uint8_t) (path[i] >> 16U);
        raw_pubkey[offset + 2U] = (uint8_t) (path[i] >> 8U);
        raw_pubkey[offset + 3U] = (uint8_t) path[i];
    }
    if (chain_code != NULL) {
        memset(chain_code, 0, 32);
    }
    return CX_OK;
}
