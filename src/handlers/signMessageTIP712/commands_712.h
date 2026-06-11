#pragma once

#include <stdbool.h>
#include <stdint.h>

#define DOMAIN_STRUCT_NAME "EIP712Domain"

uint16_t handleTIP712StructDef(uint8_t p2, const uint8_t *cdata, uint8_t length);
uint16_t handleTIP712StructImpl(uint8_t p1,
                                uint8_t p2,
                                const uint8_t *cdata,
                                uint8_t length);
uint16_t handleTIP712Sign(const uint8_t *cdata, uint8_t length);
uint16_t handleTIP712Filtering(uint8_t p1,
                               uint8_t p2,
                               const uint8_t *cdata,
                               uint8_t length);
void handle_tip712_return_code(bool success);
