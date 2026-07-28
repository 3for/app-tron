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
#include "create_smart_contract_stream.h"

#include <limits.h>
#include <string.h>

// java-tron's SmartContract ABI is field 3. It is intentionally omitted from
// the signing-time nanopb schema and treated as opaque metadata here.
#define JAVA_TRON_SMART_CONTRACT_ABI_TAG 3U

static bool create_name_is_printable(const uint8_t *data, size_t len) {
    for (size_t i = 0U; i < len; i++) {
        if ((data[i] < 0x20U) || (data[i] > 0x7eU)) {
            return false;
        }
    }
    return true;
}

static create_smart_contract_context_t current_context(
    const create_smart_contract_stream_t *stream) {
    return stream->frames[stream->depth - 1U].context;
}

static void set_error(create_smart_contract_stream_t *stream) {
    stream->error = true;
}

static void reset_varint(create_smart_contract_stream_t *stream) {
    stream->varint_value = 0;
    stream->varint_shift = 0;
    stream->varint_count = 0;
}

static bool feed_varint(create_smart_contract_stream_t *stream,
                        uint8_t byte,
                        bool *done,
                        uint64_t *value) {
    if (stream->varint_count >= 10U ||
        (stream->varint_count == 9U && byte > 1U)) {
        return false;
    }

    stream->varint_value |= ((uint64_t) (byte & 0x7FU)) << stream->varint_shift;
    stream->varint_shift = (uint8_t) (stream->varint_shift + 7U);
    stream->varint_count++;

    if ((byte & 0x80U) == 0U) {
        *done = true;
        *value = stream->varint_value;
        reset_varint(stream);
    } else {
        *done = false;
    }
    return true;
}

static bool push_frame(create_smart_contract_stream_t *stream,
                       create_smart_contract_context_t context,
                       size_t len) {
    if (stream->depth >= CREATE_SMART_CONTRACT_STREAM_MAX_NESTING) {
        return false;
    }
    stream->frames[stream->depth].context = context;
    stream->frames[stream->depth].remaining = len;
    stream->depth++;
    return true;
}

static void pop_finished_frames(create_smart_contract_stream_t *stream) {
    while (stream->depth > 0U &&
           stream->frames[stream->depth - 1U].remaining == 0U &&
           stream->mode == CREATE_SC_MODE_KEY &&
           stream->bytes_remaining == 0U &&
           stream->varint_count == 0U) {
        stream->depth--;
    }
}

static bool consume_bytes(create_smart_contract_stream_t *stream, size_t len) {
    if (stream->depth == 0U || stream->finished || stream->error ||
        stream->received_len > stream->expected_len ||
        len > stream->expected_len - stream->received_len) {
        return false;
    }

    for (size_t i = 0; i < stream->depth; i++) {
        if (stream->frames[i].remaining < len) {
            return false;
        }
    }
    for (size_t i = 0; i < stream->depth; i++) {
        stream->frames[i].remaining -= len;
    }
    stream->received_len += len;
    return true;
}

static bool is_known_varint_field(create_smart_contract_context_t context,
                                  uint32_t tag) {
    if (context == CREATE_SC_CTX_OUTER) {
        return tag == protocol_CreateSmartContract_call_token_value_tag ||
               tag == protocol_CreateSmartContract_token_id_tag;
    }
    return tag == protocol_SmartContract_call_value_tag ||
           tag == protocol_SmartContract_consume_user_resource_percent_tag ||
           tag == protocol_SmartContract_origin_energy_limit_tag ||
           tag == protocol_SmartContract_version_tag;
}

static bool is_known_length_field(create_smart_contract_context_t context,
                                  uint32_t tag) {
    if (context == CREATE_SC_CTX_OUTER) {
        return tag == protocol_CreateSmartContract_owner_address_tag ||
               tag == protocol_CreateSmartContract_new_contract_tag;
    }
    return tag == protocol_SmartContract_origin_address_tag ||
           tag == protocol_SmartContract_contract_address_tag ||
           tag == JAVA_TRON_SMART_CONTRACT_ABI_TAG ||
           tag == protocol_SmartContract_bytecode_tag ||
           tag == protocol_SmartContract_name_tag ||
           tag == protocol_SmartContract_code_hash_tag ||
           tag == protocol_SmartContract_trx_hash_tag;
}

static bool validate_known_wire_type(const create_smart_contract_stream_t *stream) {
    const create_smart_contract_context_t context = current_context(stream);
    if (is_known_varint_field(context, stream->pending_tag)) {
        return stream->pending_wire == PB_WT_VARINT;
    }
    if (is_known_length_field(context, stream->pending_tag)) {
        return stream->pending_wire == PB_WT_STRING;
    }
    return true;
}

static bool handle_varint_value(create_smart_contract_stream_t *stream,
                                uint64_t value) {
    const create_smart_contract_context_t context = current_context(stream);
    if (context == CREATE_SC_CTX_OUTER) {
        if (stream->pending_tag ==
            protocol_CreateSmartContract_call_token_value_tag) {
            if (stream->call_token_value_seen) {
                return false;
            }
            stream->call_token_value_seen = true;
            stream->contract.call_token_value = (int64_t) value;
        } else if (stream->pending_tag ==
                   protocol_CreateSmartContract_token_id_tag) {
            if (stream->token_id_seen) {
                return false;
            }
            stream->token_id_seen = true;
            stream->contract.token_id = (int64_t) value;
        }
        return true;
    }

    protocol_SmartContract *contract = &stream->contract.new_contract;
    if (stream->pending_tag == protocol_SmartContract_call_value_tag) {
        if (stream->call_value_seen) {
            return false;
        }
        stream->call_value_seen = true;
        contract->call_value = (int64_t) value;
    } else if (stream->pending_tag ==
               protocol_SmartContract_consume_user_resource_percent_tag) {
        if (stream->resource_percent_seen) {
            return false;
        }
        stream->resource_percent_seen = true;
        contract->consume_user_resource_percent = (int64_t) value;
    } else if (stream->pending_tag ==
               protocol_SmartContract_origin_energy_limit_tag) {
        if (stream->origin_energy_limit_seen) {
            return false;
        }
        stream->origin_energy_limit_seen = true;
        contract->origin_energy_limit = (int64_t) value;
    } else if (stream->pending_tag == protocol_SmartContract_version_tag) {
        if (stream->version_seen) {
            return false;
        }
        stream->version_seen = true;
        contract->version = (int32_t) (uint32_t) value;
    }
    return true;
}

static bool start_outer_length_field(create_smart_contract_stream_t *stream,
                                     size_t len) {
    if (stream->pending_tag ==
        protocol_CreateSmartContract_owner_address_tag) {
        if (stream->owner_seen || len != sizeof(stream->contract.owner_address)) {
            return false;
        }
        stream->owner_seen = true;
        stream->bytes_action = CREATE_SC_BYTES_OWNER;
        return true;
    }

    if (stream->pending_tag ==
        protocol_CreateSmartContract_new_contract_tag) {
        if (stream->new_contract_seen) {
            return false;
        }
        if (!push_frame(stream, CREATE_SC_CTX_NEW_CONTRACT, len)) {
            return false;
        }
        stream->new_contract_seen = true;
        stream->contract.has_new_contract = true;
        stream->mode = CREATE_SC_MODE_KEY;
        pop_finished_frames(stream);
        return true;
    }

    stream->bytes_action = CREATE_SC_BYTES_SKIP;
    return true;
}

static bool start_inner_length_field(create_smart_contract_stream_t *stream,
                                     size_t len) {
    protocol_SmartContract *contract = &stream->contract.new_contract;

    if (stream->pending_tag == protocol_SmartContract_origin_address_tag) {
        if (stream->origin_seen || len != sizeof(contract->origin_address)) {
            return false;
        }
        stream->origin_seen = true;
        stream->bytes_action = CREATE_SC_BYTES_ORIGIN;
    } else if (stream->pending_tag ==
               protocol_SmartContract_contract_address_tag) {
        if (stream->contract_address_seen ||
            len > sizeof(contract->contract_address.bytes)) {
            return false;
        }
        stream->contract_address_seen = true;
        contract->contract_address.size = len;
        stream->bytes_action = CREATE_SC_BYTES_SKIP;
    } else if (stream->pending_tag ==
               JAVA_TRON_SMART_CONTRACT_ABI_TAG) {
        if (stream->abi_seen) {
            return false;
        }
        stream->abi_seen = true;
        stream->abi_size = len;
        stream->bytes_action = CREATE_SC_BYTES_SKIP;
    } else if (stream->pending_tag ==
               protocol_SmartContract_bytecode_tag) {
        if (stream->bytecode_seen) {
            return false;
        }
        stream->bytecode_seen = true;
        stream->bytecode_size = len;
        stream->bytes_action = CREATE_SC_BYTES_BYTECODE;
    } else if (stream->pending_tag == protocol_SmartContract_name_tag) {
        if (stream->name_seen || len >= sizeof(contract->name)) {
            return false;
        }
        stream->name_seen = true;
        stream->bytes_action = CREATE_SC_BYTES_NAME;
    } else if (stream->pending_tag ==
               protocol_SmartContract_code_hash_tag) {
        if (stream->code_hash_seen ||
            len > sizeof(contract->code_hash.bytes)) {
            return false;
        }
        stream->code_hash_seen = true;
        contract->code_hash.size = len;
        stream->bytes_action = CREATE_SC_BYTES_SKIP;
    } else if (stream->pending_tag ==
               protocol_SmartContract_trx_hash_tag) {
        if (stream->trx_hash_seen ||
            len > sizeof(contract->trx_hash.bytes)) {
            return false;
        }
        stream->trx_hash_seen = true;
        contract->trx_hash.size = len;
        stream->bytes_action = CREATE_SC_BYTES_SKIP;
    } else {
        stream->bytes_action = CREATE_SC_BYTES_SKIP;
    }
    return true;
}

static bool start_length_field(create_smart_contract_stream_t *stream,
                               size_t len) {
    const create_smart_contract_context_t context = current_context(stream);
    stream->bytes_action = CREATE_SC_BYTES_SKIP;
    stream->capture_offset = 0U;

    bool ok;
    if (context == CREATE_SC_CTX_OUTER) {
        ok = start_outer_length_field(stream, len);
    } else {
        ok = start_inner_length_field(stream, len);
    }
    if (!ok) {
        return false;
    }

    // Entering new_contract installs its own frame and mode.
    if (context == CREATE_SC_CTX_OUTER &&
        stream->pending_tag ==
            protocol_CreateSmartContract_new_contract_tag) {
        return true;
    }

    stream->bytes_remaining = len;
    stream->mode = (len == 0U) ? CREATE_SC_MODE_KEY
                               : CREATE_SC_MODE_BYTES;
    return true;
}

static bool process_byte(create_smart_contract_stream_t *stream, uint8_t byte) {
    bool done = false;
    uint64_t value = 0;

    if (!consume_bytes(stream, 1U)) {
        return false;
    }

    switch (stream->mode) {
        case CREATE_SC_MODE_KEY:
            if (!feed_varint(stream, byte, &done, &value)) {
                return false;
            }
            if (done) {
                const uint64_t field_number = value >> 3U;
                if (field_number == 0U || field_number > 0x1FFFFFFFU) {
                    return false;
                }
                stream->pending_tag = (uint32_t) field_number;
                stream->pending_wire =
                    (pb_wire_type_t) (value & 0x07U);
                if (!validate_known_wire_type(stream)) {
                    return false;
                }
                switch (stream->pending_wire) {
                    case PB_WT_VARINT:
                        stream->mode = CREATE_SC_MODE_VARINT;
                        break;
                    case PB_WT_STRING:
                        stream->mode = CREATE_SC_MODE_LENGTH;
                        break;
                    case PB_WT_32BIT:
                        stream->bytes_action = CREATE_SC_BYTES_SKIP;
                        stream->bytes_remaining = 4U;
                        stream->mode = CREATE_SC_MODE_BYTES;
                        break;
                    case PB_WT_64BIT:
                        stream->bytes_action = CREATE_SC_BYTES_SKIP;
                        stream->bytes_remaining = 8U;
                        stream->mode = CREATE_SC_MODE_BYTES;
                        break;
                    default:
                        return false;
                }
            }
            break;

        case CREATE_SC_MODE_VARINT:
            if (!feed_varint(stream, byte, &done, &value)) {
                return false;
            }
            if (done) {
                if (!handle_varint_value(stream, value)) {
                    return false;
                }
                stream->mode = CREATE_SC_MODE_KEY;
            }
            break;

        case CREATE_SC_MODE_LENGTH:
            if (!feed_varint(stream, byte, &done, &value)) {
                return false;
            }
            if (done) {
                if (value > SIZE_MAX ||
                    value > stream->frames[stream->depth - 1U].remaining ||
                    !start_length_field(stream, (size_t) value)) {
                    return false;
                }
            }
            break;

        case CREATE_SC_MODE_BYTES:
            return false;

        default:
            return false;
    }

    pop_finished_frames(stream);
    return true;
}

static bool process_bytes_chunk(create_smart_contract_stream_t *stream,
                                const uint8_t *data,
                                size_t len) {
    if (len == 0U || len > stream->bytes_remaining ||
        !consume_bytes(stream, len)) {
        return false;
    }

    protocol_SmartContract *contract = &stream->contract.new_contract;
    switch (stream->bytes_action) {
        case CREATE_SC_BYTES_OWNER:
            if (len > sizeof(stream->contract.owner_address) -
                          stream->capture_offset) {
                return false;
            }
            memcpy(stream->contract.owner_address +
                       stream->capture_offset,
                   data,
                   len);
            stream->capture_offset += len;
            break;

        case CREATE_SC_BYTES_ORIGIN:
            if (len > sizeof(contract->origin_address) -
                          stream->capture_offset) {
                return false;
            }
            memcpy(contract->origin_address + stream->capture_offset,
                   data,
                   len);
            stream->capture_offset += len;
            break;

        case CREATE_SC_BYTES_NAME:
            if (len > sizeof(contract->name) - 1U -
                          stream->capture_offset) {
                return false;
            }
            /* This field is later consumed through C-string UI APIs. Reject
             * embedded terminators and control bytes so the reviewed name is
             * a one-to-one representation of the signed protobuf bytes. */
            if (!create_name_is_printable(data, len)) {
                return false;
            }
            memcpy(contract->name + stream->capture_offset, data, len);
            stream->capture_offset += len;
            break;

        case CREATE_SC_BYTES_BYTECODE:
            if (cx_hash_no_throw((cx_hash_t *) &stream->bytecode_hash_ctx,
                                 0,
                                 data,
                                 len,
                                 NULL,
                                 CX_SHA256_SIZE) != CX_OK) {
                return false;
            }
            break;

        case CREATE_SC_BYTES_SKIP:
            break;

        default:
            return false;
    }

    stream->bytes_remaining -= len;
    if (stream->bytes_remaining == 0U) {
        if (stream->bytes_action == CREATE_SC_BYTES_NAME) {
            contract->name[stream->capture_offset] = '\0';
        }
        stream->bytes_action = CREATE_SC_BYTES_SKIP;
        stream->capture_offset = 0U;
        stream->mode = CREATE_SC_MODE_KEY;
        pop_finished_frames(stream);
    }
    return true;
}

void create_smart_contract_stream_init(create_smart_contract_stream_t *stream,
                                       size_t parameter_len) {
    if (stream == NULL) {
        return;
    }
    memset(stream, 0, sizeof(*stream));
    stream->expected_len = parameter_len;
    stream->frames[0].context = CREATE_SC_CTX_OUTER;
    stream->frames[0].remaining = parameter_len;
    stream->depth = 1U;
    stream->mode = CREATE_SC_MODE_KEY;
    cx_sha256_init(&stream->bytecode_hash_ctx);
    pop_finished_frames(stream);
}

bool create_smart_contract_stream_feed(create_smart_contract_stream_t *stream,
                                       const uint8_t *data,
                                       size_t data_len) {
    if (stream == NULL || (data == NULL && data_len != 0U) ||
        stream->error || stream->finished ||
        stream->received_len > stream->expected_len ||
        data_len > stream->expected_len - stream->received_len) {
        if (stream != NULL) {
            set_error(stream);
        }
        return false;
    }

    size_t offset = 0U;
    while (offset < data_len) {
        if (stream->mode == CREATE_SC_MODE_BYTES) {
            size_t take = data_len - offset;
            if (take > stream->bytes_remaining) {
                take = stream->bytes_remaining;
            }
            if (!process_bytes_chunk(stream, data + offset, take)) {
                set_error(stream);
                return false;
            }
            offset += take;
        } else {
            if (!process_byte(stream, data[offset])) {
                set_error(stream);
                return false;
            }
            offset++;
        }
    }
    return true;
}

bool create_smart_contract_stream_finish(
    create_smart_contract_stream_t *stream,
    create_smart_contract_stream_result_t *result) {
    if (stream == NULL || result == NULL || stream->error ||
        stream->finished || stream->depth != 0U ||
        stream->received_len != stream->expected_len ||
        stream->mode != CREATE_SC_MODE_KEY ||
        stream->bytes_remaining != 0U || stream->varint_count != 0U) {
        if (stream != NULL) {
            set_error(stream);
        }
        return false;
    }

    memset(result, 0, sizeof(*result));
    result->contract = stream->contract;
    result->bytecode_size = stream->bytecode_size;
    result->abi_size = stream->abi_size;
    if (cx_hash_no_throw((cx_hash_t *) &stream->bytecode_hash_ctx,
                         CX_LAST,
                         NULL,
                         0,
                         result->bytecode_hash,
                         sizeof(result->bytecode_hash)) != CX_OK) {
        set_error(stream);
        return false;
    }

    stream->finished = true;
    return true;
}
