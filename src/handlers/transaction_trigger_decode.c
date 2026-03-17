#include <string.h>

#include "transaction_trigger_decode.h"

#include "core/Contract.pb.h"
#include "google/protobuf/any.pb.h"

static size_t min_size(size_t a, size_t b) {
    return (a < b) ? a : b;
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

    dec->varint_value |= ((uint64_t) (byte & 0x7FU)) << dec->varint_shift;
    dec->varint_shift = (uint8_t) (dec->varint_shift + 7U);
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
            return dec->first_contract_seen ? TRON_ACT_SKIP : TRON_ACT_ENTER_CONTRACT;
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
        return true;
    }

    if (ctx != TRON_CTX_TRIGGER) return true;

    if (dec->pending_tag == protocol_TriggerSmartContract_owner_address_tag) {
        if (dec->result.has_owner_address) {
            return false;
        }
        dec->capture_buf = dec->result.owner_address;
        dec->capture_cap = sizeof(dec->result.owner_address);
        dec->capture_len = 0;
        dec->result.has_owner_address = true;
        dec->result.owner_address_len = min_size(len, dec->capture_cap);
    } else if (dec->pending_tag == protocol_TriggerSmartContract_contract_address_tag) {
        if (dec->result.has_contract_address) {
            return false;
        }
        dec->capture_buf = dec->result.contract_address;
        dec->capture_cap = sizeof(dec->result.contract_address);
        dec->capture_len = 0;
        dec->result.has_contract_address = true;
        dec->result.contract_address_len = min_size(len, dec->capture_cap);
    } else if (dec->pending_tag == protocol_TriggerSmartContract_data_tag) {
        if (dec->result.has_data) {
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

    if (ctx == TRON_CTX_CONTRACT && dec->pending_tag == protocol_Transaction_Contract_parameter_tag) {
        return dec->result.has_contract_type &&
               dec->result.contract_type ==
                   protocol_Transaction_Contract_ContractType_TriggerSmartContract;
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
    dec->capture_buf = NULL;
    dec->capture_cap = 0;
    dec->capture_len = 0;
    dec->in_trigger_data = false;
    dec->trigger_data_total_len = 0;
    dec->trigger_data_offset = 0;
    if (!tron_start_capture_if_needed(dec, len)) {
        return false;
    }
    tron_start_bytes(dec, len);
    return true;
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
                dec->pending_tag = (uint32_t) (value >> 3U);
                dec->pending_wire = (pb_wire_type_t) (value & 0x07U);

                switch (dec->pending_wire) {
                    case PB_WT_VARINT:
                        dec->mode = TRON_MODE_VARINT;
                        break;
                    case PB_WT_STRING:
                        dec->mode = TRON_MODE_LENGTH;
                        break;
                    case PB_WT_32BIT:
                        dec->pending_action = TRON_ACT_SKIP;
                        tron_start_bytes(dec, 4U);
                        break;
                    case PB_WT_64BIT:
                        dec->pending_action = TRON_ACT_SKIP;
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

            if (dec->capture_buf != NULL && dec->capture_len < dec->capture_cap) {
                dec->capture_buf[dec->capture_len++] = byte;
            }

            dec->bytes_remaining--;
            if (dec->bytes_remaining == 0U) {
                if (dec->capture_buf == dec->result.data_prefix) {
                    dec->result.data_prefix_len = dec->capture_len;
                } else if (dec->capture_buf == dec->result.custom_data_prefix) {
                    dec->result.custom_data_prefix_len = dec->capture_len;
                }
                if (dec->in_trigger_data) {
                    dec->in_trigger_data = false;
                    dec->trigger_data_total_len = 0;
                    dec->trigger_data_offset = 0;
                }
                dec->mode = TRON_MODE_KEY;
            }
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

bool tron_stream_decoder_feed(tron_stream_decoder_t *dec, const uint8_t *data, size_t len) {
    if (dec == NULL || data == NULL || dec->error || dec->done) return false;

    for (size_t i = 0; i < len; i++) {
        if (!tron_process_byte(dec, data[i])) {
            tron_set_error(dec);
            return false;
        }

        if (dec->done) {
            /* Extra bytes beyond the declared total length are not allowed. */
            return (i + 1U == len);
        }
    }

    return true;
}

bool tron_stream_decoder_is_done(const tron_stream_decoder_t *dec) {
    return dec != NULL && dec->done && !dec->error;
}

bool tron_stream_decoder_get_result(const tron_stream_decoder_t *dec, tron_decode_result_t *out) {
    if (dec == NULL || out == NULL || dec->error || !dec->done) return false;
    *out = dec->result;
    return true;
}
