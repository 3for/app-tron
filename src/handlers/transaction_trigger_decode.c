#include <string.h>

#include "transaction_trigger_decode.h"

#include "core/Contract.pb.h"
#include "google/protobuf/any.pb.h"

static const uint8_t tron_trigger_type_url[] = "type.googleapis.com/protocol.TriggerSmartContract";
static const size_t tron_trigger_type_url_len = sizeof(tron_trigger_type_url) - 1U;
static const uint32_t tron_max_field_number = 0x1FFFFFFFU;

static size_t min_size(size_t a, size_t b) {
    return (a < b) ? a : b;
}

static void tron_reset_bytes_state(tron_stream_decoder_t *dec) {
    dec->capture_buf = NULL;
    dec->capture_cap = 0;
    dec->capture_len = 0;
    dec->validating_type_url = false;
    dec->type_url_offset = 0;
    dec->in_trigger_data = false;
    dec->trigger_data_total_len = 0;
    dec->trigger_data_offset = 0;
    dec->in_custom_data = false;
    dec->custom_data_total_len = 0;
    dec->custom_data_offset = 0;
}

/* ---------------- Streaming / APDU-friendly decoder ----------------
 *
 * Nanopb's pb_decode() cannot pause/resume across multiple APDU frames.
 * The following minimal wire-format state machine can be fed chunk-by-chunk
 * without requiring a full transaction buffer in RAM.
 *
 * It only parses the fields we care about for this demo:
 * - Transaction.raw_data.contract[0].type
 * - Transaction.raw_data.fee_limit
 * - TriggerSmartContract.{owner_address, contract_address, call_value}
 */
static tron_ctx_t tron_current_ctx(const tron_stream_decoder_t *dec) {
    if (dec->depth == 0) return TRON_CTX_TX;
    return dec->frames[dec->depth - 1U].ctx;
}

static void tron_set_error(tron_stream_decoder_t *dec) {
    dec->error = true;
}

static bool tron_push_frame(tron_stream_decoder_t *dec, tron_ctx_t ctx, size_t len) {
    if (dec->depth >= (sizeof(dec->frames) / sizeof(dec->frames[0]))) return false;
    dec->frames[dec->depth].ctx = ctx;
    dec->frames[dec->depth].remaining = len;
    dec->depth++;
    return true;
}

static void tron_pop_finished_frames(tron_stream_decoder_t *dec) {
    while (dec->depth > 0 && dec->frames[dec->depth - 1U].remaining == 0U) {
        dec->depth--;
    }
    dec->done = (dec->depth == 0U && dec->mode == TRON_MODE_KEY && dec->bytes_remaining == 0U &&
                 dec->varint_count == 0U);
}

/* Each consumed byte reduces the remaining count of all active frames. */
static bool tron_consume_byte(tron_stream_decoder_t *dec) {
    if (dec->done || dec->depth == 0U) return false;

    for (size_t i = 0; i < dec->depth; i++) {
        if (dec->frames[i].remaining == 0U) return false;
        dec->frames[i].remaining--;
    }

    return true;
}

/* Chunk equivalent of tron_consume_byte(): every active bounded frame moves
 * by exactly the same amount as the field-level bytes_remaining counter. */
static bool tron_consume_bytes(tron_stream_decoder_t *dec, size_t count) {
    if (dec->done || (dec->depth == 0U) || (count == 0U)) return false;

    for (size_t i = 0U; i < dec->depth; i++) {
        if (dec->frames[i].remaining < count) return false;
    }
    for (size_t i = 0U; i < dec->depth; i++) {
        dec->frames[i].remaining -= count;
    }
    return true;
}

static void tron_varint_reset(tron_stream_decoder_t *dec) {
    dec->varint_value = 0;
    dec->varint_shift = 0;
    dec->varint_count = 0;
}

static bool tron_varint_feed(tron_stream_decoder_t *dec,
                             uint8_t byte,
                             bool *out_done,
                             uint64_t *out_value) {
    if (dec->varint_count >= 10U) return false;
    if (dec->varint_count == 9U && byte > 1U) return false;

    dec->varint_value |= ((uint64_t)(byte & 0x7FU)) << dec->varint_shift;
    dec->varint_shift = (uint8_t)(dec->varint_shift + 7U);
    dec->varint_count++;

    if ((byte & 0x80U) == 0U) {
        *out_done = true;
        *out_value = dec->varint_value;
        tron_varint_reset(dec);
    } else {
        *out_done = false;
    }

    return true;
}

static bool tron_field_wire_is_allowed(tron_ctx_t ctx,
                                       uint32_t tag,
                                       pb_wire_type_t wire) {
    switch (ctx) {
        case TRON_CTX_TX:
            return ((tag == protocol_Transaction_raw_data_tag) ||
                    (tag == protocol_Transaction_signature_tag) ||
                    (tag == protocol_Transaction_ret_tag)) &&
                   (wire == PB_WT_STRING);
        case TRON_CTX_RAW:
            switch (tag) {
                case 1:   /* ref_block_bytes */
                case 4:   /* ref_block_hash */
                case protocol_Transaction_raw_custom_data_tag:
                case protocol_Transaction_raw_contract_tag:
                    return wire == PB_WT_STRING;
                case 3:   /* ref_block_num */
                case 8:   /* expiration */
                case 14:  /* timestamp */
                case protocol_Transaction_raw_fee_limit_tag:
                    return wire == PB_WT_VARINT;
                default:
                    return false;
            }
        case TRON_CTX_CONTRACT:
            switch (tag) {
                case protocol_Transaction_Contract_type_tag:
                case protocol_Transaction_Contract_Permission_id_tag:
                    return wire == PB_WT_VARINT;
                case protocol_Transaction_Contract_parameter_tag:
                    return wire == PB_WT_STRING;
                default:
                    return false;
            }
        case TRON_CTX_ANY:
            return ((tag == google_protobuf_Any_type_url_tag) ||
                    (tag == google_protobuf_Any_value_tag)) &&
                   (wire == PB_WT_STRING);
        case TRON_CTX_TRIGGER:
            switch (tag) {
                case protocol_TriggerSmartContract_owner_address_tag:
                case protocol_TriggerSmartContract_contract_address_tag:
                case protocol_TriggerSmartContract_data_tag:
                    return wire == PB_WT_STRING;
                case protocol_TriggerSmartContract_call_value_tag:
                case protocol_TriggerSmartContract_call_token_value_tag:
                case protocol_TriggerSmartContract_token_id_tag:
                    return wire == PB_WT_VARINT;
                default:
                    return false;
            }
        default:
            return false;
    }
}

static bool tron_field_may_repeat(tron_ctx_t ctx, uint32_t tag) {
    return ((ctx == TRON_CTX_TX) &&
            ((tag == protocol_Transaction_signature_tag) ||
             (tag == protocol_Transaction_ret_tag)));
}

static bool tron_mark_field_seen(tron_stream_decoder_t *dec,
                                 tron_ctx_t ctx,
                                 uint32_t tag) {
    uint32_t mask;

    if (tron_field_may_repeat(ctx, tag)) {
        return true;
    }
    if (tag >= 32U) {
        return false;
    }
    mask = (uint32_t) 1U << tag;
    if ((dec->seen_fields[ctx] & mask) != 0U) {
        return false;
    }
    dec->seen_fields[ctx] |= mask;
    return true;
}

static tron_action_t tron_length_action(const tron_stream_decoder_t *dec,
                                        uint32_t tag,
                                        pb_wire_type_t wire) {
    if (wire != PB_WT_STRING) return TRON_ACT_SKIP;

    const tron_ctx_t ctx = tron_current_ctx(dec);
    switch (ctx) {
        case TRON_CTX_TX:
            return (tag == protocol_Transaction_raw_data_tag) ? TRON_ACT_ENTER_RAW : TRON_ACT_SKIP;
        case TRON_CTX_RAW:
            if (tag != protocol_Transaction_raw_contract_tag) {
                return TRON_ACT_SKIP;
            }
            return TRON_ACT_ENTER_CONTRACT;
        case TRON_CTX_CONTRACT:
            return (tag == protocol_Transaction_Contract_parameter_tag) ? TRON_ACT_ENTER_ANY
                                                                        : TRON_ACT_SKIP;
        case TRON_CTX_ANY:
            return (tag == google_protobuf_Any_value_tag) ? TRON_ACT_ENTER_TRIGGER : TRON_ACT_SKIP;
        case TRON_CTX_TRIGGER:
            /* owner_address / contract_address will be captured in-place. */
            return TRON_ACT_SKIP;
        default:
            return TRON_ACT_SKIP;
    }
}

static void tron_handle_varint_value(tron_stream_decoder_t *dec, uint64_t value) {
    const tron_ctx_t ctx = tron_current_ctx(dec);

    if (ctx == TRON_CTX_RAW && dec->pending_tag == protocol_Transaction_raw_fee_limit_tag) {
        if (dec->result.has_fee_limit) {
            tron_set_error(dec);
            return;
        }
        if (value > INT64_MAX) {
            tron_set_error(dec);
            return;
        }
        dec->result.has_fee_limit = true;
        dec->result.fee_limit = (int64_t) value;
    } else if (ctx == TRON_CTX_CONTRACT &&
               dec->pending_tag == protocol_Transaction_Contract_type_tag) {
        if (dec->result.has_contract_type) {
            tron_set_error(dec);
            return;
        }
        dec->result.has_contract_type = true;
        dec->result.contract_type = (protocol_Transaction_Contract_ContractType) value;
        if (dec->result.contract_type !=
            protocol_Transaction_Contract_ContractType_TriggerSmartContract) {
            tron_set_error(dec);
        }
    } else if (ctx == TRON_CTX_CONTRACT &&
               dec->pending_tag == protocol_Transaction_Contract_Permission_id_tag) {
        if (dec->result.has_permission_id) {
            tron_set_error(dec);
            return;
        }
        if (value > UINT8_MAX) {
            tron_set_error(dec);
            return;
        }
        dec->result.has_permission_id = true;
        dec->result.permission_id = (uint32_t) value;
    } else if (ctx == TRON_CTX_TRIGGER &&
               dec->pending_tag == protocol_TriggerSmartContract_call_value_tag) {
        if (dec->result.has_call_value) {
            tron_set_error(dec);
            return;
        }
        if (value > INT64_MAX) {
            tron_set_error(dec);
            return;
        }
        dec->result.has_call_value = true;
        dec->result.call_value = (int64_t) value;
    } else if (ctx == TRON_CTX_TRIGGER &&
               dec->pending_tag == protocol_TriggerSmartContract_call_token_value_tag) {
        if (dec->result.has_call_token_value) {
            tron_set_error(dec);
            return;
        }
        if (value > INT64_MAX) {
            tron_set_error(dec);
            return;
        }
        dec->result.has_call_token_value = true;
        dec->result.call_token_value = (int64_t) value;
    } else if (ctx == TRON_CTX_TRIGGER &&
               dec->pending_tag == protocol_TriggerSmartContract_token_id_tag) {
        if (dec->result.has_token_id) {
            tron_set_error(dec);
            return;
        }
        if (value > INT64_MAX) {
            tron_set_error(dec);
            return;
        }
        dec->result.has_token_id = true;
        dec->result.token_id = (int64_t) value;
    }
}

static void tron_start_bytes(tron_stream_decoder_t *dec, size_t len) {
    dec->bytes_remaining = len;
    dec->mode = (len == 0U) ? TRON_MODE_KEY : TRON_MODE_BYTES;
}

static bool tron_start_capture_if_needed(tron_stream_decoder_t *dec, size_t len) {
    const tron_ctx_t ctx = tron_current_ctx(dec);
    if (dec->pending_wire != PB_WT_STRING) return true;

    if (ctx == TRON_CTX_RAW && dec->pending_tag == protocol_Transaction_raw_custom_data_tag) {
        if (dec->result.has_custom_data) {
            return false;
        }
        dec->result.has_custom_data = true;
        dec->result.custom_data_len = len;
        dec->capture_buf = dec->result.custom_data_prefix;
        dec->capture_cap = sizeof(dec->result.custom_data_prefix);
        dec->capture_len = 0;
        dec->result.custom_data_prefix_len = min_size(len, dec->capture_cap);
        dec->in_custom_data = true;
        dec->custom_data_total_len = len;
        dec->custom_data_offset = 0;
        return true;
    }

    if (ctx == TRON_CTX_ANY && dec->pending_tag == google_protobuf_Any_type_url_tag) {
        if (dec->type_url_seen || len != tron_trigger_type_url_len) {
            return false;
        }
        dec->type_url_seen = true;
        dec->validating_type_url = true;
        dec->type_url_offset = 0;
        return true;
    }

    if (ctx != TRON_CTX_TRIGGER) return true;

    if (dec->pending_tag == protocol_TriggerSmartContract_owner_address_tag) {
        if (dec->result.has_owner_address || (len != sizeof(dec->result.owner_address))) {
            return false;
        }
        dec->capture_buf = dec->result.owner_address;
        dec->capture_cap = sizeof(dec->result.owner_address);
        dec->capture_len = 0;
        dec->result.has_owner_address = true;
        dec->result.owner_address_len = min_size(len, dec->capture_cap);
    } else if (dec->pending_tag == protocol_TriggerSmartContract_contract_address_tag) {
        if (dec->result.has_contract_address ||
            (len != sizeof(dec->result.contract_address))) {
            return false;
        }
        dec->capture_buf = dec->result.contract_address;
        dec->capture_cap = sizeof(dec->result.contract_address);
        dec->capture_len = 0;
        dec->result.has_contract_address = true;
        dec->result.contract_address_len = min_size(len, dec->capture_cap);
    } else if (dec->pending_tag == protocol_TriggerSmartContract_data_tag) {
        if (dec->result.has_data || (len < 4U)) {
            return false;
        }
        dec->result.has_data = true;
        dec->result.data_len = len;
        dec->capture_buf = dec->result.data_prefix;
        dec->capture_cap = sizeof(dec->result.data_prefix);
        dec->capture_len = 0;
        dec->result.data_prefix_len = min_size(len, dec->capture_cap);
        dec->in_trigger_data = true;
        dec->trigger_data_total_len = len;
        dec->trigger_data_offset = 0;
    }

    return true;
}

static bool tron_enter_submessage(tron_stream_decoder_t *dec, tron_action_t action, size_t len) {
    tron_ctx_t next_ctx;
    switch (action) {
        case TRON_ACT_ENTER_RAW:
            next_ctx = TRON_CTX_RAW;
            break;
        case TRON_ACT_ENTER_CONTRACT:
            next_ctx = TRON_CTX_CONTRACT;
            break;
        case TRON_ACT_ENTER_ANY:
            next_ctx = TRON_CTX_ANY;
            break;
        case TRON_ACT_ENTER_TRIGGER:
            next_ctx = TRON_CTX_TRIGGER;
            break;
        default:
            return false;
    }

    if (!tron_push_frame(dec, next_ctx, len)) return false;
    if (action == TRON_ACT_ENTER_CONTRACT) {
        if (dec->first_contract_seen) {
            return false;
        }
        dec->first_contract_seen = true;
    }

    /* If len is zero, we immediately pop and continue. */
    tron_pop_finished_frames(dec);
    return true;
}

static bool tron_length_fits_remaining(const tron_stream_decoder_t *dec, uint64_t len) {
    if (dec->depth == 0U) {
        return false;
    }
    return len <= (uint64_t) dec->frames[dec->depth - 1U].remaining;
}

static bool tron_validate_length_field(const tron_stream_decoder_t *dec) {
    const tron_ctx_t ctx = tron_current_ctx(dec);

    if (ctx == TRON_CTX_CONTRACT &&
        dec->pending_tag == protocol_Transaction_Contract_parameter_tag) {
        return dec->result.has_contract_type &&
               dec->result.contract_type ==
                   protocol_Transaction_Contract_ContractType_TriggerSmartContract;
    }

    if (ctx == TRON_CTX_ANY && dec->pending_tag == google_protobuf_Any_value_tag) {
        return dec->type_url_seen;
    }

    if (ctx == TRON_CTX_TRIGGER && dec->pending_tag == protocol_TriggerSmartContract_data_tag) {
        return dec->result.has_owner_address && dec->result.has_contract_address;
    }

    return true;
}

static bool tron_process_length(tron_stream_decoder_t *dec, size_t len) {
    const tron_action_t action = tron_length_action(dec, dec->pending_tag, dec->pending_wire);

    if (action == TRON_ACT_ENTER_RAW || action == TRON_ACT_ENTER_CONTRACT ||
        action == TRON_ACT_ENTER_ANY || action == TRON_ACT_ENTER_TRIGGER) {
        if (action == TRON_ACT_ENTER_ANY) {
            if (dec->parameter_seen) {
                return false;
            }
            dec->parameter_seen = true;
        } else if (action == TRON_ACT_ENTER_TRIGGER) {
            if (dec->any_value_seen) {
                return false;
            }
            dec->any_value_seen = true;
        }
        dec->mode = TRON_MODE_KEY;
        return tron_enter_submessage(dec, action, len);
    }

    /* Otherwise treat it as a bytes field and skip/capture. */
    tron_reset_bytes_state(dec);
    if (!tron_start_capture_if_needed(dec, len)) {
        return false;
    }
    tron_start_bytes(dec, len);
    if (len == 0U) {
        tron_reset_bytes_state(dec);
    }
    return true;
}

static bool tron_finish_bytes(tron_stream_decoder_t *dec) {
    if (dec->capture_buf == dec->result.data_prefix) {
        dec->result.data_prefix_len = dec->capture_len;
    } else if (dec->capture_buf == dec->result.custom_data_prefix) {
        dec->result.custom_data_prefix_len = dec->capture_len;
    }
    if (dec->validating_type_url &&
        (dec->type_url_offset != tron_trigger_type_url_len)) {
        return false;
    }
    tron_reset_bytes_state(dec);
    dec->mode = TRON_MODE_KEY;
    tron_pop_finished_frames(dec);
    return true;
}

static bool tron_process_bytes_chunk(tron_stream_decoder_t *dec,
                                     const uint8_t *data,
                                     size_t count) {
    size_t capture_count = 0U;

    if ((dec == NULL) || (data == NULL) || (dec->mode != TRON_MODE_BYTES) ||
        (count == 0U) || (count > dec->bytes_remaining)) {
        return false;
    }
    /* Validate frame accounting before observers cause external side effects. */
    for (size_t i = 0U; i < dec->depth; i++) {
        if (dec->frames[i].remaining < count) return false;
    }
    if (dec->validating_type_url) {
        if ((dec->type_url_offset > tron_trigger_type_url_len) ||
            (count > (tron_trigger_type_url_len - dec->type_url_offset)) ||
            (memcmp(&tron_trigger_type_url[dec->type_url_offset], data, count) != 0)) {
            return false;
        }
    }
    if (dec->in_trigger_data && (dec->trigger_data_observer != NULL) &&
        !dec->trigger_data_observer(dec->trigger_data_observer_ctx,
                                    data,
                                    count,
                                    dec->trigger_data_offset,
                                    dec->trigger_data_total_len)) {
        return false;
    }
    if (dec->in_custom_data && (dec->custom_data_observer != NULL) &&
        !dec->custom_data_observer(dec->custom_data_observer_ctx,
                                   data,
                                   count,
                                   dec->custom_data_offset,
                                   dec->custom_data_total_len)) {
        return false;
    }
    if ((dec->capture_buf != NULL) && (dec->capture_len < dec->capture_cap)) {
        capture_count = min_size(count, dec->capture_cap - dec->capture_len);
        memcpy(&dec->capture_buf[dec->capture_len], data, capture_count);
    }
    if (!tron_consume_bytes(dec, count)) {
        return false;
    }
    dec->capture_len += capture_count;
    if (dec->validating_type_url) dec->type_url_offset += count;
    if (dec->in_trigger_data) dec->trigger_data_offset += count;
    if (dec->in_custom_data) dec->custom_data_offset += count;
    dec->bytes_remaining -= count;

    return (dec->bytes_remaining != 0U) || tron_finish_bytes(dec);
}

static bool tron_process_byte(tron_stream_decoder_t *dec, uint8_t byte) {
    if (!tron_consume_byte(dec)) return false;

    bool ok = true;
    bool done = false;
    uint64_t value = 0;

    switch (dec->mode) {
        case TRON_MODE_KEY:
            if (!tron_varint_feed(dec, byte, &done, &value)) {
                ok = false;
                break;
            }
            if (done) {
                const uint64_t field_number = value >> 3U;

                if (field_number > (uint64_t) tron_max_field_number) {
                    ok = false;
                    break;
                }

                dec->pending_tag = (uint32_t) field_number;
                dec->pending_wire = (pb_wire_type_t)(value & 0x07U);

                /* Protobuf field numbers start at 1; tag 0 is always invalid. */
                if (dec->pending_tag == 0U) {
                    ok = false;
                    break;
                }
                const tron_ctx_t ctx = tron_current_ctx(dec);
                if (!tron_field_wire_is_allowed(ctx, dec->pending_tag, dec->pending_wire) ||
                    !tron_mark_field_seen(dec, ctx, dec->pending_tag)) {
                    ok = false;
                    break;
                }

                switch (dec->pending_wire) {
                    case PB_WT_VARINT:
                        dec->mode = TRON_MODE_VARINT;
                        break;
                    case PB_WT_STRING:
                        dec->mode = TRON_MODE_LENGTH;
                        break;
                    case PB_WT_32BIT:
                        dec->pending_action = TRON_ACT_SKIP;
                        tron_reset_bytes_state(dec);
                        tron_start_bytes(dec, 4U);
                        break;
                    case PB_WT_64BIT:
                        dec->pending_action = TRON_ACT_SKIP;
                        tron_reset_bytes_state(dec);
                        tron_start_bytes(dec, 8U);
                        break;
                    default:
                        ok = false;
                        break;
                }
            }
            break;

        case TRON_MODE_VARINT:
            if (!tron_varint_feed(dec, byte, &done, &value)) {
                ok = false;
                break;
            }
            if (done) {
                tron_handle_varint_value(dec, value);
                if (dec->error) {
                    ok = false;
                    break;
                }
                dec->mode = TRON_MODE_KEY;
            }
            break;

        case TRON_MODE_LENGTH:
            if (!tron_varint_feed(dec, byte, &done, &value)) {
                ok = false;
                break;
            }
            if (done) {
                if (!tron_length_fits_remaining(dec, value) || !tron_validate_length_field(dec)) {
                    ok = false;
                    break;
                }
                ok = tron_process_length(dec, (size_t) value);
            }
            break;

        case TRON_MODE_BYTES:
            if (dec->bytes_remaining == 0U) {
                dec->mode = TRON_MODE_KEY;
                break;
            }

            if (dec->validating_type_url) {
                if (dec->type_url_offset >= tron_trigger_type_url_len ||
                    byte != tron_trigger_type_url[dec->type_url_offset]) {
                    ok = false;
                    break;
                }
                dec->type_url_offset++;
            }

            if (dec->in_trigger_data) {
                if (dec->trigger_data_observer != NULL) {
                    if (!dec->trigger_data_observer(dec->trigger_data_observer_ctx,
                                                    &byte,
                                                    1,
                                                    dec->trigger_data_offset,
                                                    dec->trigger_data_total_len)) {
                        ok = false;
                        break;
                    }
                }
                dec->trigger_data_offset++;
            }

            if (dec->in_custom_data) {
                if (dec->custom_data_observer != NULL) {
                    if (!dec->custom_data_observer(dec->custom_data_observer_ctx,
                                                   &byte,
                                                   1,
                                                   dec->custom_data_offset,
                                                   dec->custom_data_total_len)) {
                        ok = false;
                        break;
                    }
                }
                dec->custom_data_offset++;
            }

            if (dec->capture_buf != NULL && dec->capture_len < dec->capture_cap) {
                dec->capture_buf[dec->capture_len++] = byte;
            }

            dec->bytes_remaining--;
            if ((dec->bytes_remaining == 0U) && !tron_finish_bytes(dec)) ok = false;
            break;

        default:
            ok = false;
            break;
    }

    if (ok) {
        /* Pop frames only after processing the current byte in its context. */
        tron_pop_finished_frames(dec);
    }

    return ok;
}

void tron_stream_decoder_init(tron_stream_decoder_t *dec, size_t total_len) {
    if (dec == NULL) {
        return;
    }
    memset(dec, 0, sizeof(*dec));
    dec->mode = TRON_MODE_KEY;
    tron_varint_reset(dec);
    dec->done = (total_len == 0U);

    if (!dec->done) {
        (void) tron_push_frame(dec, TRON_CTX_TX, total_len);
    }
}

void tron_stream_decoder_init_raw(tron_stream_decoder_t *dec, size_t total_len) {
    if (dec == NULL) {
        return;
    }
    memset(dec, 0, sizeof(*dec));
    dec->mode = TRON_MODE_KEY;
    tron_varint_reset(dec);
    dec->done = (total_len == 0U);

    if (!dec->done) {
        (void) tron_push_frame(dec, TRON_CTX_RAW, total_len);
    }
}

void tron_stream_decoder_set_trigger_data_observer(tron_stream_decoder_t *dec,
                                                   tron_trigger_data_observer_t observer,
                                                   void *ctx) {
    if (dec == NULL) {
        return;
    }
    dec->trigger_data_observer = observer;
    dec->trigger_data_observer_ctx = ctx;
}

void tron_stream_decoder_set_custom_data_observer(tron_stream_decoder_t *dec,
                                                  tron_trigger_data_observer_t observer,
                                                  void *ctx) {
    if (dec == NULL) {
        return;
    }
    dec->custom_data_observer = observer;
    dec->custom_data_observer_ctx = ctx;
}

bool tron_stream_decoder_feed(tron_stream_decoder_t *dec, const uint8_t *data, size_t len) {
    if (dec == NULL || data == NULL || dec->error || dec->done) return false;

    size_t offset = 0U;
    while (offset < len) {
        if (dec->mode == TRON_MODE_BYTES) {
            const size_t count = min_size(dec->bytes_remaining, len - offset);
            if (!tron_process_bytes_chunk(dec, &data[offset], count)) {
                tron_set_error(dec);
                return false;
            }
            offset += count;
        } else if (!tron_process_byte(dec, data[offset++])) {
            tron_set_error(dec);
            return false;
        }

        if (dec->done) {
            /* Extra bytes beyond the declared total length are not allowed. */
            return offset == len;
        }
    }

    return true;
}

bool tron_stream_decoder_is_done(const tron_stream_decoder_t *dec) {
    return dec != NULL && dec->done && !dec->error;
}

bool tron_stream_decoder_get_result(const tron_stream_decoder_t *dec, tron_decode_result_t *out) {
    if (dec == NULL || out == NULL || dec->error || !dec->done) return false;
    if (!dec->first_contract_seen || !dec->parameter_seen || !dec->type_url_seen ||
        !dec->any_value_seen || !dec->result.has_contract_type ||
        (dec->result.contract_type !=
         protocol_Transaction_Contract_ContractType_TriggerSmartContract) ||
        !dec->result.has_owner_address || (dec->result.owner_address_len != 21U) ||
        (dec->result.owner_address[0] != 0x41U) ||
        !dec->result.has_contract_address || (dec->result.contract_address_len != 21U) ||
        (dec->result.contract_address[0] != 0x41U) || !dec->result.has_data) {
        return false;
    }
    *out = dec->result;
    return true;
}
