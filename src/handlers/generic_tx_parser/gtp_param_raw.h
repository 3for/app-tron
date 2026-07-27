#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"
#include "gtp_value.h"

// Forward declaration to avoid circular dependency
struct s_field;

typedef struct {
    uint8_t version;
    s_value value;
} s_param_raw;

typedef struct {
    s_param_raw *param;
} s_param_raw_context;

bool handle_param_raw_struct(const buffer_t *buf, s_param_raw_context *context);
bool format_uint(const struct s_field *field,
                 bool *to_be_displayed,
                 s_parsed_value *value,
                 char *buf,
                 size_t buf_size);
bool format_int(const s_value *def,
                const s_parsed_value *value,
                char *buf,
                size_t buf_size);
bool format_param_raw(const struct s_field *field);
