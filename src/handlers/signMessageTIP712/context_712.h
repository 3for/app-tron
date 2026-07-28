#pragma once

#include <stdbool.h>
#include "common_utils.h"
#include "lists.h"
#include "lcx_sha256.h"
#include "bip32_utils.h"

typedef struct {
    uint8_t contract_addr[ADDRESS_LENGTH];
    uint64_t chain_id;
    uint8_t schema_hash[CX_SHA224_SIZE];
    bool go_home_on_failure;
    bool chain_id_seen;
    bool chain_id_fits_u64;
    bool schema_locked;
    bool signing_path_locked;
    bip32_path_t signing_path;
} s_tip712_context;

extern s_tip712_context *tip712_context;

typedef enum {
    TIP712_PHASE_NONE = 0,
    TIP712_PHASE_FULL_BUILDING,
    TIP712_PHASE_FULL_REVIEW,
    TIP712_PHASE_LEGACY_REVIEW,
} tip712_phase_t;

bool tip712_context_init(void);
bool tip712_lock_signing_path(const uint8_t *data, size_t length);
const bip32_path_t *tip712_get_signing_path(void);
void tip712_context_cleanup(void);
void tip712_context_deinit(void);
tip712_phase_t tip712_get_phase(void);
bool tip712_full_session_in_progress(void);
bool tip712_review_in_progress(void);
bool tip712_mark_reviewing(void);
bool tip712_mark_legacy_reviewing(void);

typedef enum { NOT_INITIALIZED, INITIALIZED, DEFINED } e_struct_init;
extern e_struct_init struct_state;
