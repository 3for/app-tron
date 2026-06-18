#pragma once

#include <stdint.h>
#include "bip32.h"

typedef struct {
    uint32_t indices[MAX_BIP32_PATH];
    uint8_t length;
} bip32_path_t;