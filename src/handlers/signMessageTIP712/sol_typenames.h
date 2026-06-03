#pragma once

#include <stdbool.h>
#include <stdint.h>

bool sol_typenames_init(void);
void sol_typenames_deinit(void);

const char *get_struct_field_sol_typename(const void *ptr, uint8_t *length);
