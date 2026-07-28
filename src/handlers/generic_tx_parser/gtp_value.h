#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"
#include "gtp_data_path.h"
#include "calldata.h"
#include "common_utils.h"

typedef enum {
    TF_UINT = 1,
    TF_INT,
    TF_UFIXED,
    TF_FIXED,
    TF_ADDRESS,
    TF_BOOL,
    TF_BYTES,
    TF_STRING,
    // TVM trcToken: a token id, encoded exactly like uint256.
    TF_TRC_TOKEN,
} e_type_family;

typedef enum {
    CP_FROM = 0,
    CP_TO,
    CP_VALUE,
    CP_CHAIN_ID,
} e_container_path;

typedef enum {
    SOURCE_CALLDATA,
    SOURCE_RLP,
    SOURCE_CONSTANT,
} e_value_source;

typedef struct {
    uint8_t size;
    uint8_t buf[CALLDATA_CHUNK_SIZE];
} s_constant;

typedef struct {
    uint8_t version;
    e_type_family type_family;
    uint8_t type_size;
    union {
        s_data_path data_path;
        e_container_path container_path;
        s_constant constant;
    };
    e_value_source source;
} s_value;

typedef struct {
    s_value *value;
} s_value_context;

bool handle_value_struct(const buffer_t *buf, s_value_context *context);
bool value_get(const s_value *value, s_parsed_value_collection *collection);
void value_cleanup(const s_value *value, const s_parsed_value_collection *collection);
bool parsed_value_to_uint_be(const s_parsed_value *value, uint8_t *out, size_t out_size);
bool parsed_value_to_address(const s_parsed_value *value, uint8_t out[static ADDRESS_LENGTH]);
bool parsed_value_to_selector(const s_parsed_value *value,
                              uint8_t out[static CALLDATA_SELECTOR_SIZE]);
