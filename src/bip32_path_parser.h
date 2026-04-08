#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

static inline uint32_t read_u32_be_bytes(const uint8_t *buffer) {
    return ((uint32_t) buffer[0] << 24) | ((uint32_t) buffer[1] << 16) |
           ((uint32_t) buffer[2] << 8) | (uint32_t) buffer[3];
}

static inline off_t read_bip32_path_words(const uint8_t *buffer,
                                          size_t length,
                                          uint8_t *path_length_out,
                                          uint32_t *path_words,
                                          size_t max_bip32_path) {
    unsigned int path_length;

    if ((buffer == NULL) || (path_length_out == NULL) || (path_words == NULL) || (length < 1U)) {
        return -1;
    }

    path_length = *buffer++;
    if ((path_length < 1U) || (path_length > max_bip32_path) ||
        (length < (1U + 4U * path_length))) {
        return -1;
    }

    *path_length_out = (uint8_t) path_length;
    for (unsigned int i = 0; i < path_length; i++) {
        path_words[i] = read_u32_be_bytes(buffer);
        buffer += 4;
    }

    return (off_t)(1U + 4U * path_length);
}
