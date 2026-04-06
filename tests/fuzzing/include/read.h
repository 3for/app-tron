#pragma once

#include <stdint.h>

static inline uint16_t read_u16_be(const uint8_t *buffer, uint16_t offset) {
    const uint8_t *p = buffer + offset;
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static inline uint32_t read_u32_be(const uint8_t *buffer, uint16_t offset) {
    const uint8_t *p = buffer + offset;
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) |
           (uint32_t) p[3];
}

static inline uint64_t read_u64_be(const uint8_t *buffer, uint16_t offset) {
    const uint8_t *p = buffer + offset;
    uint64_t v = 0;

    for (size_t i = 0; i < sizeof(uint64_t); i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

#define U4BE(buffer, offset) read_u32_be((buffer), (offset))
