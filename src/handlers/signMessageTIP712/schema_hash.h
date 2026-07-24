#pragma once

#include <stdbool.h>
#include "lcx_sha256.h"

bool compute_schema_hash(void);
bool compute_schema_hash_into(uint8_t out[CX_SHA224_SIZE]);
