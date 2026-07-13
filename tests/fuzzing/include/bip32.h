#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef MAX_BIP32_PATH
#define MAX_BIP32_PATH 10
#endif

static inline bool bip32_path_read(const uint8_t *buffer,
                                   size_t buffer_len,
                                   uint32_t *path,
                                   uint8_t path_len) {
    if ((buffer == NULL) || (path == NULL) || (path_len > MAX_BIP32_PATH) ||
        (buffer_len != (size_t) path_len * sizeof(uint32_t))) {
        return false;
    }
    for (uint8_t i = 0; i < path_len; i++) {
        const size_t offset = (size_t) i * sizeof(uint32_t);
        path[i] = ((uint32_t) buffer[offset] << 24U) |
                  ((uint32_t) buffer[offset + 1U] << 16U) |
                  ((uint32_t) buffer[offset + 2U] << 8U) |
                  (uint32_t) buffer[offset + 3U];
    }
    return true;
}
