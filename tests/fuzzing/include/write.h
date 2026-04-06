#pragma once

#include <stdint.h>

static inline void write_u64_be(uint8_t *buffer, uint16_t offset, uint64_t value) {
    uint8_t *p = buffer + offset;

    for (size_t i = 0; i < sizeof(uint64_t); i++) {
        p[sizeof(uint64_t) - 1U - i] = (uint8_t) (value & 0xFFU);
        value >>= 8;
    }
}
