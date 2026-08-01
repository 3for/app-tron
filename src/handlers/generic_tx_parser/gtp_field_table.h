#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "gtp_field.h"
#include "trusted_name.h"

typedef struct {
    e_param_type type;
    char *key;
    char *value;
    const void *extra_data;
    bool start_intent;  // This pair starts a new transaction in a batch
    bool end_intent;    // This pair ends a transaction in a batch
    bool owns_extra_data;
} s_field_table_entry;

bool field_table_init(void);
void field_table_cleanup(void);
bool add_to_field_table(e_param_type type,
                        const char *key,
                        const char *value,
                        const void *extra_data);
bool add_to_field_table_with_extra_data_copy(e_param_type type,
                                             const char *key,
                                             const char *value,
                                             const void *extra_data,
                                             size_t extra_data_size);
bool set_intent_field(const char *value);
size_t field_table_size(void);
const s_field_table_entry *get_from_field_table(int index);
