#pragma once

#include <stdbool.h>
#include <stdint.h>

#define DOMAIN_STRUCT_NAME "EIP712Domain"

int handleTIP712StructDef(uint8_t p1,
                          uint8_t p2,
                          uint8_t *workBuffer,
                          uint16_t dataLength,
                          uint8_t ins);
int handleTIP712StructImpl(uint8_t p1,
                           uint8_t p2,
                           uint8_t *workBuffer,
                           uint16_t dataLength,
                           uint8_t ins);
int handleTIP712Sign(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength);
int handleTIP712Filtering(uint8_t p1,
                          uint8_t p2,
                          uint8_t *workBuffer,
                          uint16_t dataLength,
                          uint8_t ins);
void handle_tip712_return_code(bool success);
