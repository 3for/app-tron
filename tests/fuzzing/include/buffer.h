#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *ptr;
    size_t size;
    size_t offset;
} buffer_t;
