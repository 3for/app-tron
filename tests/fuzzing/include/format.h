#pragma once

#include <stddef.h>
#include <stdint.h>

static inline int format_hex(const void *value, size_t len, char *out, size_t out_len) {
    static const char hex[] = "0123456789abcdef";
    const uint8_t *bytes = (const uint8_t *) value;

    if (out_len < (len * 2U + 1U)) {
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        out[2U * i] = hex[(bytes[i] >> 4) & 0x0FU];
        out[2U * i + 1U] = hex[bytes[i] & 0x0FU];
    }
    out[len * 2U] = '\0';
    return (int) (len * 2U);
}
