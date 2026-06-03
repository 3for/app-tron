#pragma once

#include <stdbool.h>
#include <stdint.h>

bool app_mem_init(void);
char *mem_alloc_and_format_uint(uint32_t value);
