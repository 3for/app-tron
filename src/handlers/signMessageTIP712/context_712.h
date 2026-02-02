#pragma once

#include <stdbool.h>
#include "parse.h"

typedef struct {
    uint8_t contract_addr[ADDRESS_LENGTH];
    uint64_t chain_id;
    uint8_t schema_hash[224 / 8];
    bool go_home_on_failure;
} s_tip712_context;

extern s_tip712_context *tip712_context;

bool tip712_context_init(void);
void tip712_context_deinit(void);

typedef enum { NOT_INITIALIZED, INITIALIZED, DEFINED } e_struct_init;
extern e_struct_init struct_state;
