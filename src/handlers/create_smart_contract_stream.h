/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2026 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/Contract.pb.h"
#include "cx.h"
#include "pb.h"

#define CREATE_SMART_CONTRACT_STREAM_MAX_NESTING 2U

typedef enum {
    CREATE_SC_CTX_OUTER = 0,
    CREATE_SC_CTX_NEW_CONTRACT,
} create_smart_contract_context_t;

typedef struct {
    create_smart_contract_context_t context;
    size_t remaining;
} create_smart_contract_frame_t;

typedef enum {
    CREATE_SC_MODE_KEY = 0,
    CREATE_SC_MODE_VARINT,
    CREATE_SC_MODE_LENGTH,
    CREATE_SC_MODE_BYTES,
} create_smart_contract_mode_t;

typedef enum {
    CREATE_SC_BYTES_SKIP = 0,
    CREATE_SC_BYTES_OWNER,
    CREATE_SC_BYTES_ORIGIN,
    CREATE_SC_BYTES_NAME,
    CREATE_SC_BYTES_BYTECODE,
} create_smart_contract_bytes_action_t;

typedef struct create_smart_contract_stream_result_s {
    protocol_CreateSmartContract contract;
    uint64_t bytecode_size;
    uint8_t bytecode_hash[CX_SHA256_SIZE];
    uint64_t abi_size;
} create_smart_contract_stream_result_t;

typedef struct {
    create_smart_contract_frame_t frames[CREATE_SMART_CONTRACT_STREAM_MAX_NESTING];
    size_t depth;
    size_t expected_len;
    size_t received_len;

    create_smart_contract_mode_t mode;
    create_smart_contract_bytes_action_t bytes_action;
    uint32_t pending_tag;
    pb_wire_type_t pending_wire;

    uint64_t varint_value;
    uint8_t varint_shift;
    uint8_t varint_count;
    size_t bytes_remaining;
    size_t capture_offset;

    bool owner_seen;
    bool new_contract_seen;
    bool call_token_value_seen;
    bool token_id_seen;
    bool origin_seen;
    bool contract_address_seen;
    bool abi_seen;
    bool bytecode_seen;
    bool call_value_seen;
    bool resource_percent_seen;
    bool name_seen;
    bool origin_energy_limit_seen;
    bool code_hash_seen;
    bool trx_hash_seen;
    bool version_seen;
    bool error;
    bool finished;

    uint64_t abi_size;
    uint64_t bytecode_size;
    cx_sha256_t bytecode_hash_ctx;
    protocol_CreateSmartContract contract;
} create_smart_contract_stream_t;

void create_smart_contract_stream_init(create_smart_contract_stream_t *stream,
                                       size_t parameter_len);
bool create_smart_contract_stream_feed(create_smart_contract_stream_t *stream,
                                       const uint8_t *data,
                                       size_t data_len);
bool create_smart_contract_stream_finish(create_smart_contract_stream_t *stream,
                                         create_smart_contract_stream_result_t *result);
