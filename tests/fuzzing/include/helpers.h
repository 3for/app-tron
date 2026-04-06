#pragma once

#include <sys/types.h>
#include "parse.h"

off_t read_bip32_path_712(const uint8_t *buffer,
                          uint16_t length,
                          messageSigningContext712_t *ctx_712);
