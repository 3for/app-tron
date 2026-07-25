#pragma once

#include <stdint.h>

#include "read.h"

// IO flag set by signing handlers to defer the APDU reply (value matches the SDK).
#ifndef IO_ASYNCH_REPLY
#define IO_ASYNCH_REPLY (1 << 8)
#endif

int io_send_sw(uint16_t sw);
int io_send_response_pointer(const uint8_t *buffer, uint16_t tx, uint16_t sw);
