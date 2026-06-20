#pragma once
// Host-side mock of the SDK <base58.h>. The fuzz build does not need real Base58
// output (no address is parsed back); produce a deterministic placeholder so the
// TRON address-formatting paths in common_utils.c link and run.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline int base58_encode(const uint8_t *in, size_t length, char *out, size_t maxoutlen) {
    (void) in;
    (void) length;
    if ((out == NULL) || (maxoutlen == 0U)) {
        return -1;
    }
    size_t n = (maxoutlen > 1U) ? (maxoutlen - 1U) : 0U;
    memset(out, 'T', n);
    out[n] = '\0';
    return (int) n;
}
