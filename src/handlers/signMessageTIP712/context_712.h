#pragma once

#include <stdbool.h>
#include "common_utils.h"
#include "lists.h"
#include "lcx_sha256.h"

typedef struct {
    uint8_t contract_addr[ADDRESS_LENGTH];
    uint64_t chain_id;
    uint8_t schema_hash[CX_SHA224_SIZE];
    bool go_home_on_failure;
    bool chain_id_seen;
    bool chain_id_fits_u64;
    bool schema_locked;
    bool review_in_progress;
} s_tip712_context;

extern s_tip712_context *tip712_context;

bool tip712_context_init(void);
void tip712_context_cleanup(void);
void tip712_context_deinit(void);
bool tip712_review_in_progress(void);
void tip712_mark_reviewing(void);

typedef enum { NOT_INITIALIZED, INITIALIZED, DEFINED } e_struct_init;
extern e_struct_init struct_state;
