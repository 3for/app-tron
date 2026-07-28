#pragma once

#include <stdint.h>
#include <stdbool.h>

#define TIP_712_ENCODED_FIELD_LENGTH 32

bool encode_uint(const uint8_t *value,
                 uint8_t length,
                 uint8_t out[TIP_712_ENCODED_FIELD_LENGTH]);
bool encode_int(const uint8_t *value,
                uint8_t length,
                uint8_t typesize,
                uint8_t out[TIP_712_ENCODED_FIELD_LENGTH]);
bool encode_boolean(const uint8_t *value,
                    uint8_t length,
                    uint8_t out[TIP_712_ENCODED_FIELD_LENGTH]);
bool encode_address(const uint8_t *value,
                    uint8_t length,
                    uint8_t out[TIP_712_ENCODED_FIELD_LENGTH]);
bool encode_bytes(const uint8_t *value,
                  uint8_t length,
                  uint8_t out[TIP_712_ENCODED_FIELD_LENGTH]);
