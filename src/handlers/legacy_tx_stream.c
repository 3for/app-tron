#include "legacy_tx_stream.h"

#include <limits.h>
#include <string.h>

#include "google/protobuf/any.pb.h"

static const uint8_t TYPE_URL_PREFIX[] = "type.googleapis.com/protocol.";

enum {
    LEGACY_TX_RAW_REF_BLOCK_BYTES_TAG = 1U,
    LEGACY_TX_RAW_REF_BLOCK_NUM_TAG = 3U,
    LEGACY_TX_RAW_REF_BLOCK_HASH_TAG = 4U,
    LEGACY_TX_RAW_EXPIRATION_TAG = 8U,
    LEGACY_TX_RAW_TIMESTAMP_TAG = 14U,
};

#define LEGACY_TX_REF_BLOCK_BYTES_SIZE 2U
#define LEGACY_TX_REF_BLOCK_HASH_SIZE  8U

static legacy_tx_context_t current_context(const legacy_tx_stream_t *stream) {
    return stream->frames[stream->depth - 1U].context;
}

static bool field_wire_is_allowed(legacy_tx_context_t context,
                                  uint32_t tag,
                                  pb_wire_type_t wire) {
    switch (context) {
        case LEGACY_TX_CTX_RAW:
            switch (tag) {
                case LEGACY_TX_RAW_REF_BLOCK_BYTES_TAG:
                case LEGACY_TX_RAW_REF_BLOCK_HASH_TAG:
                case protocol_Transaction_raw_custom_data_tag:
                case protocol_Transaction_raw_contract_tag:
                    return wire == PB_WT_STRING;
                case LEGACY_TX_RAW_REF_BLOCK_NUM_TAG:
                case LEGACY_TX_RAW_EXPIRATION_TAG:
                case LEGACY_TX_RAW_TIMESTAMP_TAG:
                case protocol_Transaction_raw_fee_limit_tag:
                    return wire == PB_WT_VARINT;
                default:
                    return false;
            }
        case LEGACY_TX_CTX_CONTRACT:
            switch (tag) {
                case protocol_Transaction_Contract_type_tag:
                case protocol_Transaction_Contract_Permission_id_tag:
                    return wire == PB_WT_VARINT;
                case protocol_Transaction_Contract_parameter_tag:
                    return wire == PB_WT_STRING;
                default:
                    return false;
            }
        case LEGACY_TX_CTX_ANY:
            return ((tag == google_protobuf_Any_type_url_tag) ||
                    (tag == google_protobuf_Any_value_tag)) &&
                   (wire == PB_WT_STRING);
        default:
            return false;
    }
}

static bool mark_field_seen(legacy_tx_stream_t *stream,
                            legacy_tx_context_t context,
                            uint32_t tag) {
    if (context >= LEGACY_TX_CTX_COUNT || tag >= 32U) {
        return false;
    }

    const uint32_t mask = UINT32_C(1) << tag;
    if ((stream->seen_fields[context] & mask) != 0U) {
        return false;
    }
    stream->seen_fields[context] |= mask;
    return true;
}

static void set_error(legacy_tx_stream_t *stream) {
    stream->error = true;
}

static void reset_varint(legacy_tx_stream_t *stream) {
    stream->varint_value = 0;
    stream->varint_shift = 0;
    stream->varint_count = 0;
}

static bool feed_varint(legacy_tx_stream_t *stream, uint8_t byte, bool *done, uint64_t *value) {
    if (stream->varint_count >= 10U || (stream->varint_count == 9U && byte > 1U)) {
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

static bool push_frame(legacy_tx_stream_t *stream, legacy_tx_context_t context, size_t len) {
    if (stream->depth >= LEGACY_TX_STREAM_MAX_NESTING) {
        return false;
    }
    stream->frames[stream->depth].context = context;
    stream->frames[stream->depth].remaining = len;
    stream->frames[stream->depth].bounded = true;
    stream->depth++;
    return true;
}

static void pop_finished_frames(legacy_tx_stream_t *stream) {
    // The unbounded raw-data root is finalized explicitly by P1_SIGN/P1_LAST
    // or by the first TRC-10 metadata APDU, so it is never popped here.
    while (stream->depth > 1U && stream->frames[stream->depth - 1U].remaining == 0U &&
           stream->mode == LEGACY_TX_MODE_KEY && stream->bytes_remaining == 0U &&
           stream->varint_count == 0U) {
        stream->depth--;
    }
}

static bool consume_bytes(legacy_tx_stream_t *stream, size_t len) {
    if (stream->depth == 0U || stream->finished || stream->error) {
        return false;
    }
    for (size_t i = 0; i < stream->depth; i++) {
        if (!stream->frames[i].bounded) {
            continue;
        }
        if (stream->frames[i].remaining < len) {
            return false;
        }
    }
    for (size_t i = 0; i < stream->depth; i++) {
        if (stream->frames[i].bounded) {
            stream->frames[i].remaining -= len;
        }
    }
    return true;
}

static bool length_fits_current_frame(const legacy_tx_stream_t *stream, uint64_t len) {
    if (len > SIZE_MAX || len > LEGACY_TX_MAX_RAW_SIZE) {
        return false;
    }
    const legacy_tx_frame_t *frame = &stream->frames[stream->depth - 1U];
    return !frame->bounded || len <= frame->remaining;
}

static const char *contract_message_name(protocol_Transaction_Contract_ContractType type) {
    switch (type) {
        case protocol_Transaction_Contract_ContractType_AccountCreateContract:
            return "AccountCreateContract";
        case protocol_Transaction_Contract_ContractType_TransferContract:
            return "TransferContract";
        case protocol_Transaction_Contract_ContractType_TransferAssetContract:
            return "TransferAssetContract";
        case protocol_Transaction_Contract_ContractType_VoteWitnessContract:
            return "VoteWitnessContract";
        case protocol_Transaction_Contract_ContractType_WitnessCreateContract:
            return "WitnessCreateContract";
        case protocol_Transaction_Contract_ContractType_AssetIssueContract:
            return "AssetIssueContract";
        case protocol_Transaction_Contract_ContractType_WitnessUpdateContract:
            return "WitnessUpdateContract";
        case protocol_Transaction_Contract_ContractType_ParticipateAssetIssueContract:
            return "ParticipateAssetIssueContract";
        case protocol_Transaction_Contract_ContractType_AccountUpdateContract:
            return "AccountUpdateContract";
        case protocol_Transaction_Contract_ContractType_FreezeBalanceContract:
            return "FreezeBalanceContract";
        case protocol_Transaction_Contract_ContractType_UnfreezeBalanceContract:
            return "UnfreezeBalanceContract";
        case protocol_Transaction_Contract_ContractType_WithdrawBalanceContract:
            return "WithdrawBalanceContract";
        case protocol_Transaction_Contract_ContractType_UnfreezeAssetContract:
            return "UnfreezeAssetContract";
        case protocol_Transaction_Contract_ContractType_UpdateAssetContract:
            return "UpdateAssetContract";
        case protocol_Transaction_Contract_ContractType_ProposalCreateContract:
            return "ProposalCreateContract";
        case protocol_Transaction_Contract_ContractType_ProposalApproveContract:
            return "ProposalApproveContract";
        case protocol_Transaction_Contract_ContractType_ProposalDeleteContract:
            return "ProposalDeleteContract";
        case protocol_Transaction_Contract_ContractType_SetAccountIdContract:
            return "SetAccountIdContract";
        case protocol_Transaction_Contract_ContractType_CreateSmartContract:
            return "CreateSmartContract";
        case protocol_Transaction_Contract_ContractType_TriggerSmartContract:
            return "TriggerSmartContract";
        case protocol_Transaction_Contract_ContractType_UpdateSettingContract:
            return "UpdateSettingContract";
        case protocol_Transaction_Contract_ContractType_ExchangeCreateContract:
            return "ExchangeCreateContract";
        case protocol_Transaction_Contract_ContractType_ExchangeInjectContract:
            return "ExchangeInjectContract";
        case protocol_Transaction_Contract_ContractType_ExchangeWithdrawContract:
            return "ExchangeWithdrawContract";
        case protocol_Transaction_Contract_ContractType_ExchangeTransactionContract:
            return "ExchangeTransactionContract";
        case protocol_Transaction_Contract_ContractType_UpdateEnergyLimitContract:
            return "UpdateEnergyLimitContract";
        case protocol_Transaction_Contract_ContractType_AccountPermissionUpdateContract:
            return "AccountPermissionUpdateContract";
        case protocol_Transaction_Contract_ContractType_ClearABIContract:
            return "ClearABIContract";
        case protocol_Transaction_Contract_ContractType_UpdateBrokerageContract:
            return "UpdateBrokerageContract";
        case protocol_Transaction_Contract_ContractType_FreezeBalanceV2Contract:
            return "FreezeBalanceV2Contract";
        case protocol_Transaction_Contract_ContractType_UnfreezeBalanceV2Contract:
            return "UnfreezeBalanceV2Contract";
        case protocol_Transaction_Contract_ContractType_WithdrawExpireUnfreezeContract:
            return "WithdrawExpireUnfreezeContract";
        case protocol_Transaction_Contract_ContractType_DelegateResourceContract:
            return "DelegateResourceContract";
        case protocol_Transaction_Contract_ContractType_UnDelegateResourceContract:
            return "UnDelegateResourceContract";
        case protocol_Transaction_Contract_ContractType_CancelAllUnfreezeV2Contract:
            return "CancelAllUnfreezeV2Contract";
        default:
            return NULL;
    }
}

static bool type_url_matches_contract(const legacy_tx_stream_t *stream) {
    const char *name = contract_message_name(stream->contract_type);
    if (name == NULL) {
        return false;
    }
    const size_t prefix_len = sizeof(TYPE_URL_PREFIX) - 1U;
    const size_t name_len = strlen(name);
    return stream->type_url_len == prefix_len + name_len &&
           memcmp(stream->type_url, TYPE_URL_PREFIX, prefix_len) == 0 &&
           memcmp(stream->type_url + prefix_len, name, name_len) == 0;
}

static bool handle_varint_value(legacy_tx_stream_t *stream, uint64_t value) {
    const legacy_tx_context_t context = current_context(stream);
    if (context == LEGACY_TX_CTX_RAW &&
        stream->pending_tag == protocol_Transaction_raw_fee_limit_tag) {
        if (stream->fee_limit_seen || value > INT64_MAX) {
            return false;
        }
        stream->fee_limit_seen = true;
        stream->fee_limit = (int64_t) value;
    } else if (context == LEGACY_TX_CTX_RAW &&
               ((stream->pending_tag == LEGACY_TX_RAW_REF_BLOCK_NUM_TAG) ||
                (stream->pending_tag == LEGACY_TX_RAW_EXPIRATION_TAG) ||
                (stream->pending_tag == LEGACY_TX_RAW_TIMESTAMP_TAG))) {
        if (value > INT64_MAX) {
            return false;
        }
    } else if (context == LEGACY_TX_CTX_CONTRACT &&
               stream->pending_tag == protocol_Transaction_Contract_type_tag) {
        if (stream->contract_type_seen || value > INT32_MAX) {
            return false;
        }
        stream->contract_type_seen = true;
        stream->contract_type = (protocol_Transaction_Contract_ContractType) value;
    } else if (context == LEGACY_TX_CTX_CONTRACT &&
               stream->pending_tag == protocol_Transaction_Contract_Permission_id_tag) {
        if (stream->permission_id_seen || value > INT32_MAX) {
            return false;
        }
        stream->permission_id_seen = true;
        stream->permission_id = (int32_t) value;
    }
    return true;
}

static bool start_length_field(legacy_tx_stream_t *stream, size_t len) {
    const legacy_tx_context_t context = current_context(stream);
    stream->bytes_action = LEGACY_TX_BYTES_SKIP;
    stream->capture_offset = 0;

    if ((context == LEGACY_TX_CTX_RAW) &&
        (((stream->pending_tag == LEGACY_TX_RAW_REF_BLOCK_BYTES_TAG) &&
          (len != LEGACY_TX_REF_BLOCK_BYTES_SIZE)) ||
         ((stream->pending_tag == LEGACY_TX_RAW_REF_BLOCK_HASH_TAG) &&
          (len != LEGACY_TX_REF_BLOCK_HASH_SIZE)))) {
        return false;
    }

    if (context == LEGACY_TX_CTX_RAW &&
        stream->pending_tag == protocol_Transaction_raw_contract_tag) {
        if (stream->contract_seen) {
            return false;
        }
        stream->contract_seen = true;
        stream->mode = LEGACY_TX_MODE_KEY;
        if (!push_frame(stream, LEGACY_TX_CTX_CONTRACT, len)) {
            return false;
        }
        pop_finished_frames(stream);
        return true;
    }

    if (context == LEGACY_TX_CTX_RAW &&
        stream->pending_tag == protocol_Transaction_raw_custom_data_tag) {
        if (stream->custom_data_seen) {
            return false;
        }
        stream->custom_data_seen = true;
        stream->custom_data_len = len;
    } else if (context == LEGACY_TX_CTX_CONTRACT &&
               stream->pending_tag == protocol_Transaction_Contract_parameter_tag) {
        if (stream->parameter_message_seen) {
            return false;
        }
        stream->parameter_message_seen = true;
        stream->mode = LEGACY_TX_MODE_KEY;
        if (!push_frame(stream, LEGACY_TX_CTX_ANY, len)) {
            return false;
        }
        pop_finished_frames(stream);
        return true;
    } else if (context == LEGACY_TX_CTX_ANY &&
               stream->pending_tag == google_protobuf_Any_type_url_tag) {
        if (stream->type_url_seen || len > sizeof(stream->type_url)) {
            return false;
        }
        stream->type_url_seen = true;
        stream->type_url_len = len;
        stream->bytes_action = LEGACY_TX_BYTES_TYPE_URL;
    } else if (context == LEGACY_TX_CTX_ANY &&
               stream->pending_tag == google_protobuf_Any_value_tag) {
        if (stream->parameter_seen) {
            return false;
        }
        stream->parameter_seen = true;
        stream->parameter_len = len;
        stream->parameter_capture_len = 0U;
        stream->parameter_overflow = len > sizeof(stream->parameter);
        stream->bytes_action = LEGACY_TX_BYTES_PARAMETER;
        if (stream->parameter_observer.on_begin != NULL) {
            stream->parameter_observer.on_begin(stream->parameter_observer.ctx, len);
        }
        if (len == 0U && stream->parameter_observer.on_end != NULL) {
            stream->parameter_observer.on_end(stream->parameter_observer.ctx);
        }
    }

    stream->bytes_remaining = len;
    stream->mode = (len == 0U) ? LEGACY_TX_MODE_KEY : LEGACY_TX_MODE_BYTES;
    return true;
}

static bool process_byte(legacy_tx_stream_t *stream, uint8_t byte) {
    bool done = false;
    uint64_t value = 0;

    if (!consume_bytes(stream, 1U)) {
        return false;
    }

    switch (stream->mode) {
        case LEGACY_TX_MODE_KEY:
            if (!feed_varint(stream, byte, &done, &value)) {
                return false;
            }
            if (done) {
                uint64_t field_number = value >> 3U;
                if (field_number == 0U || field_number > 0x1FFFFFFFU) {
                    return false;
                }
                stream->pending_tag = (uint32_t) field_number;
                stream->pending_wire = (pb_wire_type_t) (value & 0x07U);
                const legacy_tx_context_t context = current_context(stream);
                if (!field_wire_is_allowed(context,
                                           stream->pending_tag,
                                           stream->pending_wire) ||
                    !mark_field_seen(stream, context, stream->pending_tag)) {
                    return false;
                }
                switch (stream->pending_wire) {
                    case PB_WT_VARINT:
                        stream->mode = LEGACY_TX_MODE_VARINT;
                        break;
                    case PB_WT_STRING:
                        stream->mode = LEGACY_TX_MODE_LENGTH;
                        break;
                    default:
                        return false;
                }
            }
            break;

        case LEGACY_TX_MODE_VARINT:
            if (!feed_varint(stream, byte, &done, &value)) {
                return false;
            }
            if (done) {
                if (!handle_varint_value(stream, value)) {
                    return false;
                }
                stream->mode = LEGACY_TX_MODE_KEY;
            }
            break;

        case LEGACY_TX_MODE_LENGTH:
            if (!feed_varint(stream, byte, &done, &value)) {
                return false;
            }
            if (done) {
                if (!length_fits_current_frame(stream, value) ||
                    !start_length_field(stream, (size_t) value)) {
                    return false;
                }
            }
            break;

        case LEGACY_TX_MODE_BYTES:
            return false;

        default:
            return false;
    }

    pop_finished_frames(stream);
    return true;
}

static bool process_bytes_chunk(legacy_tx_stream_t *stream,
                                const uint8_t *data,
                                size_t len) {
    if (len == 0U || len > stream->bytes_remaining ||
        !consume_bytes(stream, len)) {
        return false;
    }

    if (stream->bytes_action == LEGACY_TX_BYTES_TYPE_URL) {
        if (len > sizeof(stream->type_url) - stream->capture_offset) {
            return false;
        }
        memcpy(stream->type_url + stream->capture_offset, data, len);
        stream->capture_offset += len;
    } else if (stream->bytes_action == LEGACY_TX_BYTES_PARAMETER) {
        if (!stream->parameter_overflow) {
            if (len > sizeof(stream->parameter) -
                          stream->parameter_capture_len) {
                return false;
            }
            memcpy(stream->parameter + stream->parameter_capture_len,
                   data,
                   len);
            stream->parameter_capture_len += len;
        }
        if (stream->parameter_observer.on_chunk != NULL) {
            stream->parameter_observer.on_chunk(stream->parameter_observer.ctx,
                                                data,
                                                len);
        }
    }

    stream->bytes_remaining -= len;
    if (stream->bytes_remaining == 0U) {
        if (stream->bytes_action == LEGACY_TX_BYTES_PARAMETER &&
            stream->parameter_observer.on_end != NULL) {
            stream->parameter_observer.on_end(stream->parameter_observer.ctx);
        }
        stream->mode = LEGACY_TX_MODE_KEY;
        stream->bytes_action = LEGACY_TX_BYTES_SKIP;
        stream->capture_offset = 0U;
        pop_finished_frames(stream);
    }
    return true;
}

void legacy_tx_stream_init(legacy_tx_stream_t *stream,
                           const legacy_parameter_observer_t *observer) {
    if (stream == NULL) {
        return;
    }
    memset(stream, 0, sizeof(*stream));
    if (observer != NULL) {
        stream->parameter_observer = *observer;
    }
    stream->frames[0].context = LEGACY_TX_CTX_RAW;
    stream->frames[0].bounded = false;
    stream->depth = 1U;
    stream->mode = LEGACY_TX_MODE_KEY;
    // Proto3 omits scalar fields set to their default values.
    stream->contract_type = protocol_Transaction_Contract_ContractType_AccountCreateContract;
}

bool legacy_tx_stream_feed(legacy_tx_stream_t *stream, const uint8_t *data, size_t len) {
    if (stream == NULL || (data == NULL && len != 0U) || stream->error || stream->finished ||
        len > LEGACY_TX_MAX_RAW_SIZE - stream->total_len) {
        if (stream != NULL) {
            set_error(stream);
        }
        return false;
    }

    size_t offset = 0U;
    while (offset < len) {
        if (stream->mode == LEGACY_TX_MODE_BYTES) {
            size_t take = len - offset;
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
    stream->total_len += len;
    return true;
}

bool legacy_tx_stream_finish(legacy_tx_stream_t *stream, legacy_tx_stream_result_t *result) {
    if (stream == NULL || result == NULL || stream->error || stream->finished ||
        stream->total_len == 0U || stream->depth != 1U || stream->mode != LEGACY_TX_MODE_KEY ||
        stream->bytes_remaining != 0U || stream->varint_count != 0U || !stream->contract_seen ||
        !stream->parameter_message_seen || !stream->type_url_seen || !stream->parameter_seen ||
        (!stream->parameter_overflow &&
         stream->parameter_capture_len != stream->parameter_len) ||
        (stream->parameter_overflow && stream->parameter_capture_len != 0U) ||
        !type_url_matches_contract(stream)) {
        if (stream != NULL) {
            set_error(stream);
        }
        return false;
    }

    stream->finished = true;
    result->contract_type = stream->contract_type;
    result->permission_id = stream->permission_id;
    result->fee_limit = stream->fee_limit;
    result->custom_data_len = stream->custom_data_len;
    result->raw_data_size = stream->total_len;
    result->parameter = stream->parameter_overflow ? NULL : stream->parameter;
    result->parameter_len = stream->parameter_len;
    result->parameter_overflow = stream->parameter_overflow;
    return true;
}
