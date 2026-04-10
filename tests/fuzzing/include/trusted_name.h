#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "common_utils.h"

#define TRUSTED_NAME_MAX_LENGTH 30

typedef enum {
    TN_TYPE_ACCOUNT = 1,
    TN_TYPE_CONTRACT,
    TN_TYPE_NFT_COLLECTION,
    TN_TYPE_TOKEN,
    TN_TYPE_WALLET,
    TN_TYPE_CONTEXT_ADDRESS,
    _TN_TYPE_COUNT_,
} e_name_type;

#define TN_TYPE_COUNT (_TN_TYPE_COUNT_ - TN_TYPE_ACCOUNT)

typedef enum {
    TN_SOURCE_LAB = 0,
    TN_SOURCE_CAL,
    TN_SOURCE_ENS,
    TN_SOURCE_UD,
    TN_SOURCE_FN,
    TN_SOURCE_DNS,
    TN_SOURCE_DYNAMIC_RESOLVER,
    TN_SOURCE_MAB,
    TN_SOURCE_COUNT,
} e_name_source;

extern char g_trusted_name[TRUSTED_NAME_MAX_LENGTH + 1];

const char *get_trusted_name(uint8_t type_count,
                             const e_name_type *types,
                             uint8_t source_count,
                             const e_name_source *sources,
                             const uint64_t *chain_id,
                             const uint8_t *addr);
bool has_trusted_name(void);
