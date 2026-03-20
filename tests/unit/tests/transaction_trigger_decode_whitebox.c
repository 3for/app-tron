#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#define static
#include "../../../src/handlers/transaction_trigger_decode.c"
#undef static

static void reset_decoder(tron_stream_decoder_t *decoder) {
    memset(decoder, 0, sizeof(*decoder));
}

static void set_ctx(tron_stream_decoder_t *decoder, tron_ctx_t ctx) {
    reset_decoder(decoder);
    decoder->depth = 1U;
    decoder->frames[0].ctx = ctx;
    decoder->frames[0].remaining = 16U;
}

static void prepare_process_byte(tron_stream_decoder_t *decoder,
                                 tron_mode_t mode,
                                 tron_ctx_t ctx,
                                 size_t remaining) {
    set_ctx(decoder, ctx);
    decoder->mode = mode;
    decoder->frames[0].remaining = remaining;
}

static bool observer_reject(void *ctx,
                            const uint8_t *chunk,
                            size_t chunk_len,
                            size_t chunk_offset,
                            size_t total_len) {
    (void) ctx;
    (void) chunk;
    (void) chunk_len;
    (void) chunk_offset;
    (void) total_len;
    return false;
}

static void test_helper_state_mutators(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    reset_decoder(&decoder);
    decoder.capture_buf = decoder.result.data_prefix;
    decoder.capture_cap = 3U;
    decoder.capture_len = 2U;
    decoder.validating_type_url = true;
    decoder.type_url_offset = 9U;
    decoder.in_trigger_data = true;
    decoder.trigger_data_total_len = 7U;
    decoder.trigger_data_offset = 4U;

    assert_int_equal(min_size(1U, 2U), 1U);
    assert_int_equal(min_size(3U, 2U), 2U);

    tron_reset_bytes_state(&decoder);
    assert_null(decoder.capture_buf);
    assert_int_equal(decoder.capture_cap, 0U);
    assert_int_equal(decoder.capture_len, 0U);
    assert_false(decoder.validating_type_url);
    assert_int_equal(decoder.type_url_offset, 0U);
    assert_false(decoder.in_trigger_data);
    assert_int_equal(decoder.trigger_data_total_len, 0U);
    assert_int_equal(decoder.trigger_data_offset, 0U);

    decoder.error = false;
    tron_set_error(&decoder);
    assert_true(decoder.error);

    decoder.varint_value = 9U;
    decoder.varint_shift = 7U;
    decoder.varint_count = 2U;
    tron_varint_reset(&decoder);
    assert_int_equal(decoder.varint_value, 0U);
    assert_int_equal(decoder.varint_shift, 0U);
    assert_int_equal(decoder.varint_count, 0U);

    tron_start_bytes(&decoder, 0U);
    assert_int_equal(decoder.bytes_remaining, 0U);
    assert_int_equal(decoder.mode, TRON_MODE_KEY);

    tron_start_bytes(&decoder, 5U);
    assert_int_equal(decoder.bytes_remaining, 5U);
    assert_int_equal(decoder.mode, TRON_MODE_BYTES);
}

static void test_tron_current_ctx_and_push_frame_paths(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    reset_decoder(&decoder);
    assert_int_equal(tron_current_ctx(&decoder), TRON_CTX_TX);

    reset_decoder(&decoder);
    assert_true(tron_push_frame(&decoder, TRON_CTX_RAW, 4U));
    assert_int_equal(decoder.depth, 1U);
    assert_int_equal(decoder.frames[0].ctx, TRON_CTX_RAW);
    assert_int_equal(decoder.frames[0].remaining, 4U);
    assert_int_equal(tron_current_ctx(&decoder), TRON_CTX_RAW);

    decoder.depth = sizeof(decoder.frames) / sizeof(decoder.frames[0]);
    assert_false(tron_push_frame(&decoder, TRON_CTX_ANY, 1U));
}

static void test_tron_pop_finished_frames_and_consume_byte_paths(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    reset_decoder(&decoder);
    decoder.done = true;
    assert_false(tron_consume_byte(&decoder));

    reset_decoder(&decoder);
    assert_false(tron_consume_byte(&decoder));

    set_ctx(&decoder, TRON_CTX_TX);
    decoder.frames[0].remaining = 0U;
    assert_false(tron_consume_byte(&decoder));

    reset_decoder(&decoder);
    decoder.depth = 2U;
    decoder.mode = TRON_MODE_KEY;
    decoder.frames[0].ctx = TRON_CTX_TX;
    decoder.frames[0].remaining = 0U;
    decoder.frames[1].ctx = TRON_CTX_RAW;
    decoder.frames[1].remaining = 0U;
    tron_pop_finished_frames(&decoder);
    assert_int_equal(decoder.depth, 0U);
    assert_true(decoder.done);

    set_ctx(&decoder, TRON_CTX_RAW);
    decoder.frames[0].remaining = 2U;
    assert_true(tron_consume_byte(&decoder));
    assert_int_equal(decoder.frames[0].remaining, 1U);
}

static void test_tron_varint_feed_paths(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;
    bool done = false;
    uint64_t value = 0U;

    reset_decoder(&decoder);
    assert_true(tron_varint_feed(&decoder, 0x80U, &done, &value));
    assert_false(done);
    assert_int_equal(decoder.varint_count, 1U);

    assert_true(tron_varint_feed(&decoder, 0x01U, &done, &value));
    assert_true(done);
    assert_int_equal(value, 128U);
    assert_int_equal(decoder.varint_count, 0U);
    assert_int_equal(decoder.varint_shift, 0U);

    decoder.varint_count = 10U;
    assert_false(tron_varint_feed(&decoder, 0x00U, &done, &value));

    reset_decoder(&decoder);
    decoder.varint_count = 9U;
    decoder.varint_shift = 63U;
    assert_false(tron_varint_feed(&decoder, 0x02U, &done, &value));
}

static void test_tron_length_action_maps_contexts(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    reset_decoder(&decoder);
    assert_int_equal(tron_length_action(&decoder, 1U, PB_WT_VARINT), TRON_ACT_SKIP);

    set_ctx(&decoder, TRON_CTX_TX);
    assert_int_equal(tron_length_action(&decoder, protocol_Transaction_raw_data_tag, PB_WT_STRING),
                     TRON_ACT_ENTER_RAW);

    set_ctx(&decoder, TRON_CTX_RAW);
    assert_int_equal(tron_length_action(&decoder, protocol_Transaction_raw_fee_limit_tag, PB_WT_STRING),
                     TRON_ACT_SKIP);
    assert_int_equal(tron_length_action(&decoder, protocol_Transaction_raw_contract_tag, PB_WT_STRING),
                     TRON_ACT_ENTER_CONTRACT);
    decoder.first_contract_seen = true;
    assert_int_equal(tron_length_action(&decoder, protocol_Transaction_raw_contract_tag, PB_WT_STRING),
                     TRON_ACT_SKIP);

    set_ctx(&decoder, TRON_CTX_CONTRACT);
    assert_int_equal(
        tron_length_action(&decoder, protocol_Transaction_Contract_parameter_tag, PB_WT_STRING),
        TRON_ACT_ENTER_ANY);

    set_ctx(&decoder, TRON_CTX_ANY);
    assert_int_equal(tron_length_action(&decoder, google_protobuf_Any_value_tag, PB_WT_STRING),
                     TRON_ACT_ENTER_TRIGGER);

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    assert_int_equal(tron_length_action(&decoder, protocol_TriggerSmartContract_data_tag, PB_WT_STRING),
                     TRON_ACT_SKIP);

    set_ctx(&decoder, (tron_ctx_t) 99);
    assert_int_equal(tron_length_action(&decoder, 1U, PB_WT_STRING), TRON_ACT_SKIP);
}

static void test_tron_handle_varint_value_paths(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    set_ctx(&decoder, TRON_CTX_RAW);
    decoder.pending_tag = protocol_Transaction_raw_fee_limit_tag;
    tron_handle_varint_value(&decoder, 7U);
    assert_true(decoder.result.has_fee_limit);
    assert_int_equal(decoder.result.fee_limit, 7);

    set_ctx(&decoder, TRON_CTX_RAW);
    decoder.pending_tag = protocol_Transaction_raw_fee_limit_tag;
    decoder.result.has_fee_limit = true;
    tron_handle_varint_value(&decoder, 7U);
    assert_true(decoder.error);

    set_ctx(&decoder, TRON_CTX_RAW);
    decoder.pending_tag = protocol_Transaction_raw_fee_limit_tag;
    tron_handle_varint_value(&decoder, (uint64_t) INT64_MAX + 1U);
    assert_true(decoder.error);

    set_ctx(&decoder, TRON_CTX_CONTRACT);
    decoder.pending_tag = protocol_Transaction_Contract_type_tag;
    tron_handle_varint_value(&decoder,
                             protocol_Transaction_Contract_ContractType_TriggerSmartContract);
    assert_true(decoder.result.has_contract_type);
    assert_false(decoder.error);

    set_ctx(&decoder, TRON_CTX_CONTRACT);
    decoder.pending_tag = protocol_Transaction_Contract_type_tag;
    tron_handle_varint_value(&decoder, protocol_Transaction_Contract_ContractType_TransferContract);
    assert_true(decoder.error);

    set_ctx(&decoder, TRON_CTX_CONTRACT);
    decoder.pending_tag = protocol_Transaction_Contract_type_tag;
    decoder.result.has_contract_type = true;
    tron_handle_varint_value(&decoder,
                             protocol_Transaction_Contract_ContractType_TriggerSmartContract);
    assert_true(decoder.error);

    set_ctx(&decoder, TRON_CTX_CONTRACT);
    decoder.pending_tag = protocol_Transaction_Contract_Permission_id_tag;
    tron_handle_varint_value(&decoder, 9U);
    assert_true(decoder.result.has_permission_id);
    assert_int_equal(decoder.result.permission_id, 9U);

    set_ctx(&decoder, TRON_CTX_CONTRACT);
    decoder.pending_tag = protocol_Transaction_Contract_Permission_id_tag;
    decoder.result.has_permission_id = true;
    tron_handle_varint_value(&decoder, 9U);
    assert_true(decoder.error);

    set_ctx(&decoder, TRON_CTX_CONTRACT);
    decoder.pending_tag = protocol_Transaction_Contract_Permission_id_tag;
    tron_handle_varint_value(&decoder, 256U);
    assert_true(decoder.error);

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_tag = protocol_TriggerSmartContract_call_value_tag;
    tron_handle_varint_value(&decoder, 1U);
    assert_true(decoder.result.has_call_value);
    assert_int_equal(decoder.result.call_value, 1);

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_tag = protocol_TriggerSmartContract_call_value_tag;
    decoder.result.has_call_value = true;
    tron_handle_varint_value(&decoder, 1U);
    assert_true(decoder.error);

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_tag = protocol_TriggerSmartContract_call_value_tag;
    tron_handle_varint_value(&decoder, (uint64_t) INT64_MAX + 1U);
    assert_true(decoder.error);

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_tag = protocol_TriggerSmartContract_call_token_value_tag;
    tron_handle_varint_value(&decoder, 2U);
    assert_true(decoder.result.has_call_token_value);
    assert_int_equal(decoder.result.call_token_value, 2);

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_tag = protocol_TriggerSmartContract_call_token_value_tag;
    decoder.result.has_call_token_value = true;
    tron_handle_varint_value(&decoder, 2U);
    assert_true(decoder.error);

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_tag = protocol_TriggerSmartContract_call_token_value_tag;
    tron_handle_varint_value(&decoder, (uint64_t) INT64_MAX + 1U);
    assert_true(decoder.error);

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_tag = protocol_TriggerSmartContract_token_id_tag;
    tron_handle_varint_value(&decoder, 3U);
    assert_true(decoder.result.has_token_id);
    assert_int_equal(decoder.result.token_id, 3);

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_tag = protocol_TriggerSmartContract_token_id_tag;
    decoder.result.has_token_id = true;
    tron_handle_varint_value(&decoder, 3U);
    assert_true(decoder.error);

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_tag = protocol_TriggerSmartContract_token_id_tag;
    tron_handle_varint_value(&decoder, (uint64_t) INT64_MAX + 1U);
    assert_true(decoder.error);
}

static void test_tron_start_capture_if_needed_paths(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    set_ctx(&decoder, TRON_CTX_TX);
    decoder.pending_wire = PB_WT_VARINT;
    assert_true(tron_start_capture_if_needed(&decoder, 4U));

    set_ctx(&decoder, TRON_CTX_RAW);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_Transaction_raw_custom_data_tag;
    assert_true(tron_start_capture_if_needed(&decoder, 40U));
    assert_true(decoder.result.has_custom_data);
    assert_int_equal(decoder.result.custom_data_len, 40U);
    assert_int_equal(decoder.result.custom_data_prefix_len, sizeof(decoder.result.custom_data_prefix));
    assert_ptr_equal(decoder.capture_buf, decoder.result.custom_data_prefix);

    set_ctx(&decoder, TRON_CTX_RAW);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_Transaction_raw_custom_data_tag;
    decoder.result.has_custom_data = true;
    assert_false(tron_start_capture_if_needed(&decoder, 1U));

    set_ctx(&decoder, TRON_CTX_ANY);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = google_protobuf_Any_type_url_tag;
    assert_true(tron_start_capture_if_needed(&decoder, tron_trigger_type_url_len));
    assert_true(decoder.type_url_seen);
    assert_true(decoder.validating_type_url);
    assert_int_equal(decoder.type_url_offset, 0U);

    set_ctx(&decoder, TRON_CTX_ANY);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = google_protobuf_Any_type_url_tag;
    decoder.type_url_seen = true;
    assert_false(tron_start_capture_if_needed(&decoder, tron_trigger_type_url_len));

    set_ctx(&decoder, TRON_CTX_ANY);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = google_protobuf_Any_type_url_tag;
    assert_false(tron_start_capture_if_needed(&decoder, tron_trigger_type_url_len - 1U));

    set_ctx(&decoder, TRON_CTX_CONTRACT);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = 99U;
    assert_true(tron_start_capture_if_needed(&decoder, 2U));

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_TriggerSmartContract_owner_address_tag;
    assert_true(tron_start_capture_if_needed(&decoder, 30U));
    assert_true(decoder.result.has_owner_address);
    assert_int_equal(decoder.result.owner_address_len, sizeof(decoder.result.owner_address));

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_TriggerSmartContract_owner_address_tag;
    decoder.result.has_owner_address = true;
    assert_false(tron_start_capture_if_needed(&decoder, 1U));

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_TriggerSmartContract_contract_address_tag;
    assert_true(tron_start_capture_if_needed(&decoder, 30U));
    assert_true(decoder.result.has_contract_address);
    assert_int_equal(decoder.result.contract_address_len,
                     sizeof(decoder.result.contract_address));

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_TriggerSmartContract_contract_address_tag;
    decoder.result.has_contract_address = true;
    assert_false(tron_start_capture_if_needed(&decoder, 1U));

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_TriggerSmartContract_data_tag;
    assert_true(tron_start_capture_if_needed(&decoder, 80U));
    assert_true(decoder.result.has_data);
    assert_int_equal(decoder.result.data_len, 80U);
    assert_int_equal(decoder.result.data_prefix_len, sizeof(decoder.result.data_prefix));
    assert_true(decoder.in_trigger_data);
    assert_int_equal(decoder.trigger_data_total_len, 80U);

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_TriggerSmartContract_data_tag;
    decoder.result.has_data = true;
    assert_false(tron_start_capture_if_needed(&decoder, 1U));
}

static void test_tron_enter_submessage_and_length_validation_paths(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    reset_decoder(&decoder);
    decoder.mode = TRON_MODE_KEY;
    assert_true(tron_enter_submessage(&decoder, TRON_ACT_ENTER_RAW, 0U));
    assert_true(decoder.done);

    reset_decoder(&decoder);
    decoder.mode = TRON_MODE_KEY;
    assert_true(tron_enter_submessage(&decoder, TRON_ACT_ENTER_CONTRACT, 3U));
    assert_true(decoder.first_contract_seen);
    assert_int_equal(decoder.frames[0].ctx, TRON_CTX_CONTRACT);

    reset_decoder(&decoder);
    decoder.mode = TRON_MODE_KEY;
    assert_true(tron_enter_submessage(&decoder, TRON_ACT_ENTER_ANY, 2U));
    assert_int_equal(decoder.frames[0].ctx, TRON_CTX_ANY);

    reset_decoder(&decoder);
    decoder.mode = TRON_MODE_KEY;
    assert_true(tron_enter_submessage(&decoder, TRON_ACT_ENTER_TRIGGER, 2U));
    assert_int_equal(decoder.frames[0].ctx, TRON_CTX_TRIGGER);

    reset_decoder(&decoder);
    decoder.depth = sizeof(decoder.frames) / sizeof(decoder.frames[0]);
    assert_false(tron_enter_submessage(&decoder, TRON_ACT_ENTER_RAW, 1U));

    reset_decoder(&decoder);
    assert_false(tron_enter_submessage(&decoder, (tron_action_t) 99, 0U));

    reset_decoder(&decoder);
    assert_false(tron_length_fits_remaining(&decoder, 1U));

    set_ctx(&decoder, TRON_CTX_CONTRACT);
    decoder.pending_tag = protocol_Transaction_Contract_parameter_tag;
    assert_false(tron_validate_length_field(&decoder));
    decoder.result.has_contract_type = true;
    decoder.result.contract_type = protocol_Transaction_Contract_ContractType_TriggerSmartContract;
    assert_true(tron_validate_length_field(&decoder));
    decoder.result.contract_type = protocol_Transaction_Contract_ContractType_TransferContract;
    assert_false(tron_validate_length_field(&decoder));

    set_ctx(&decoder, TRON_CTX_ANY);
    decoder.pending_tag = google_protobuf_Any_value_tag;
    assert_false(tron_validate_length_field(&decoder));
    decoder.type_url_seen = true;
    assert_true(tron_validate_length_field(&decoder));

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_tag = protocol_TriggerSmartContract_data_tag;
    assert_false(tron_validate_length_field(&decoder));
    decoder.result.has_owner_address = true;
    assert_false(tron_validate_length_field(&decoder));
    decoder.result.has_contract_address = true;
    assert_true(tron_validate_length_field(&decoder));

    set_ctx(&decoder, TRON_CTX_TX);
    decoder.pending_tag = 99U;
    assert_true(tron_validate_length_field(&decoder));
}

static void test_tron_process_length_paths(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    set_ctx(&decoder, TRON_CTX_TX);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_Transaction_raw_data_tag;
    decoder.mode = TRON_MODE_LENGTH;
    assert_true(tron_process_length(&decoder, 3U));
    assert_int_equal(decoder.frames[1].ctx, TRON_CTX_RAW);

    set_ctx(&decoder, TRON_CTX_RAW);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_Transaction_raw_contract_tag;
    decoder.mode = TRON_MODE_LENGTH;
    assert_true(tron_process_length(&decoder, 3U));
    assert_true(decoder.first_contract_seen);
    assert_int_equal(decoder.frames[1].ctx, TRON_CTX_CONTRACT);

    set_ctx(&decoder, TRON_CTX_CONTRACT);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_Transaction_Contract_parameter_tag;
    decoder.mode = TRON_MODE_LENGTH;
    assert_true(tron_process_length(&decoder, 3U));
    assert_true(decoder.parameter_seen);
    assert_int_equal(decoder.frames[1].ctx, TRON_CTX_ANY);

    set_ctx(&decoder, TRON_CTX_CONTRACT);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_Transaction_Contract_parameter_tag;
    decoder.mode = TRON_MODE_LENGTH;
    decoder.parameter_seen = true;
    assert_false(tron_process_length(&decoder, 3U));

    set_ctx(&decoder, TRON_CTX_ANY);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = google_protobuf_Any_value_tag;
    decoder.mode = TRON_MODE_LENGTH;
    assert_true(tron_process_length(&decoder, 3U));
    assert_true(decoder.any_value_seen);
    assert_int_equal(decoder.frames[1].ctx, TRON_CTX_TRIGGER);

    set_ctx(&decoder, TRON_CTX_ANY);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = google_protobuf_Any_value_tag;
    decoder.mode = TRON_MODE_LENGTH;
    decoder.any_value_seen = true;
    assert_false(tron_process_length(&decoder, 3U));

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_TriggerSmartContract_owner_address_tag;
    decoder.mode = TRON_MODE_LENGTH;
    assert_true(tron_process_length(&decoder, 2U));
    assert_int_equal(decoder.mode, TRON_MODE_BYTES);
    assert_int_equal(decoder.bytes_remaining, 2U);

    set_ctx(&decoder, TRON_CTX_RAW);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_Transaction_raw_custom_data_tag;
    decoder.mode = TRON_MODE_LENGTH;
    decoder.result.has_custom_data = true;
    assert_false(tron_process_length(&decoder, 1U));

    set_ctx(&decoder, TRON_CTX_TRIGGER);
    decoder.pending_wire = PB_WT_STRING;
    decoder.pending_tag = protocol_TriggerSmartContract_owner_address_tag;
    decoder.mode = TRON_MODE_LENGTH;
    assert_true(tron_process_length(&decoder, 0U));
    assert_int_equal(decoder.mode, TRON_MODE_KEY);
}

static void test_tron_process_byte_key_mode_paths(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;
    static const uint8_t too_large_key[] = {0x80U, 0x80U, 0x80U, 0x80U, 0x10U};

    prepare_process_byte(&decoder, TRON_MODE_KEY, TRON_CTX_TX, 1U);
    assert_true(tron_process_byte(&decoder, 0x08U));
    assert_int_equal(decoder.mode, TRON_MODE_VARINT);

    prepare_process_byte(&decoder, TRON_MODE_KEY, TRON_CTX_TX, 1U);
    assert_true(tron_process_byte(&decoder, 0x0AU));
    assert_int_equal(decoder.mode, TRON_MODE_LENGTH);

    prepare_process_byte(&decoder, TRON_MODE_KEY, TRON_CTX_TX, 1U);
    assert_true(tron_process_byte(&decoder, 0x0DU));
    assert_int_equal(decoder.mode, TRON_MODE_BYTES);
    assert_int_equal(decoder.bytes_remaining, 4U);

    prepare_process_byte(&decoder, TRON_MODE_KEY, TRON_CTX_TX, 1U);
    assert_true(tron_process_byte(&decoder, 0x09U));
    assert_int_equal(decoder.mode, TRON_MODE_BYTES);
    assert_int_equal(decoder.bytes_remaining, 8U);

    prepare_process_byte(&decoder, TRON_MODE_KEY, TRON_CTX_TX, 1U);
    assert_false(tron_process_byte(&decoder, 0x00U));

    prepare_process_byte(&decoder, TRON_MODE_KEY, TRON_CTX_TX, 1U);
    assert_false(tron_process_byte(&decoder, 0x0EU));

    prepare_process_byte(&decoder, TRON_MODE_KEY, TRON_CTX_TX, 1U);
    decoder.varint_count = 9U;
    decoder.varint_shift = 63U;
    assert_false(tron_process_byte(&decoder, 0x02U));

    prepare_process_byte(&decoder, TRON_MODE_KEY, TRON_CTX_TX, sizeof(too_large_key));
    for (size_t i = 0; i < sizeof(too_large_key) - 1U; i++) {
        assert_true(tron_process_byte(&decoder, too_large_key[i]));
    }
    assert_false(tron_process_byte(&decoder, too_large_key[sizeof(too_large_key) - 1U]));
}

static void test_tron_process_byte_other_modes(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    prepare_process_byte(&decoder, TRON_MODE_VARINT, TRON_CTX_RAW, 1U);
    decoder.pending_tag = protocol_Transaction_raw_fee_limit_tag;
    assert_true(tron_process_byte(&decoder, 0x05U));
    assert_true(decoder.result.has_fee_limit);
    assert_int_equal(decoder.mode, TRON_MODE_KEY);

    prepare_process_byte(&decoder, TRON_MODE_VARINT, TRON_CTX_RAW, 1U);
    decoder.pending_tag = protocol_Transaction_raw_fee_limit_tag;
    decoder.result.has_fee_limit = true;
    assert_false(tron_process_byte(&decoder, 0x05U));

    prepare_process_byte(&decoder, TRON_MODE_LENGTH, TRON_CTX_TX, 1U);
    decoder.pending_tag = protocol_Transaction_raw_data_tag;
    decoder.pending_wire = PB_WT_STRING;
    assert_false(tron_process_byte(&decoder, 0x01U));

    prepare_process_byte(&decoder, TRON_MODE_LENGTH, TRON_CTX_TX, 1U);
    decoder.varint_count = 9U;
    decoder.varint_shift = 63U;
    assert_false(tron_process_byte(&decoder, 0x02U));

    prepare_process_byte(&decoder, TRON_MODE_BYTES, TRON_CTX_ANY, 1U);
    decoder.bytes_remaining = 0U;
    assert_true(tron_process_byte(&decoder, 0x00U));
    assert_int_equal(decoder.mode, TRON_MODE_KEY);

    prepare_process_byte(&decoder, TRON_MODE_BYTES, TRON_CTX_ANY, 1U);
    decoder.bytes_remaining = 1U;
    decoder.validating_type_url = true;
    assert_false(tron_process_byte(&decoder, 0x00U));

    prepare_process_byte(&decoder, TRON_MODE_BYTES, TRON_CTX_ANY, 1U);
    decoder.bytes_remaining = 1U;
    decoder.validating_type_url = true;
    assert_false(tron_process_byte(&decoder, tron_trigger_type_url[0]));

    prepare_process_byte(&decoder, TRON_MODE_BYTES, TRON_CTX_TRIGGER, 1U);
    decoder.bytes_remaining = 1U;
    decoder.in_trigger_data = true;
    decoder.trigger_data_total_len = 1U;
    decoder.trigger_data_observer = observer_reject;
    assert_false(tron_process_byte(&decoder, 0xAAU));

    prepare_process_byte(&decoder, TRON_MODE_BYTES, TRON_CTX_TRIGGER, 1U);
    decoder.bytes_remaining = 1U;
    decoder.in_trigger_data = true;
    decoder.trigger_data_total_len = 1U;
    decoder.capture_buf = decoder.result.data_prefix;
    decoder.capture_cap = sizeof(decoder.result.data_prefix);
    decoder.capture_len = 0U;
    assert_true(tron_process_byte(&decoder, 0xABU));
    assert_int_equal(decoder.result.data_prefix_len, 1U);
    assert_false(decoder.in_trigger_data);
    assert_int_equal(decoder.mode, TRON_MODE_KEY);

    prepare_process_byte(&decoder, TRON_MODE_BYTES, TRON_CTX_RAW, 1U);
    decoder.bytes_remaining = 1U;
    decoder.capture_buf = decoder.result.custom_data_prefix;
    decoder.capture_cap = sizeof(decoder.result.custom_data_prefix);
    decoder.capture_len = 0U;
    assert_true(tron_process_byte(&decoder, 0xCDU));
    assert_int_equal(decoder.result.custom_data_prefix_len, 1U);

    prepare_process_byte(&decoder, (tron_mode_t) 99, TRON_CTX_TX, 1U);
    assert_false(tron_process_byte(&decoder, 0x00U));
}

static void test_public_decoder_api_paths(void **state) {
    (void) state;

    const uint8_t byte = 0x00U;
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    tron_stream_decoder_init(NULL, 1U);
    tron_stream_decoder_init_raw(NULL, 1U);

    tron_stream_decoder_init(&decoder, 0U);
    assert_true(decoder.done);
    assert_int_equal(decoder.depth, 0U);
    assert_true(tron_stream_decoder_is_done(&decoder));

    tron_stream_decoder_init(&decoder, 3U);
    assert_false(decoder.done);
    assert_int_equal(decoder.depth, 1U);
    assert_int_equal(decoder.frames[0].ctx, TRON_CTX_TX);

    tron_stream_decoder_init_raw(&decoder, 0U);
    assert_true(decoder.done);

    tron_stream_decoder_init_raw(&decoder, 3U);
    assert_false(decoder.done);
    assert_int_equal(decoder.depth, 1U);
    assert_int_equal(decoder.frames[0].ctx, TRON_CTX_RAW);

    tron_stream_decoder_set_trigger_data_observer(NULL, observer_reject, NULL);
    tron_stream_decoder_set_trigger_data_observer(&decoder, observer_reject, &decoder);
    assert_ptr_equal(decoder.trigger_data_observer, observer_reject);
    assert_ptr_equal(decoder.trigger_data_observer_ctx, &decoder);

    assert_false(tron_stream_decoder_feed(NULL, &byte, 1U));
    assert_false(tron_stream_decoder_feed(&decoder, NULL, 1U));

    decoder.error = true;
    assert_false(tron_stream_decoder_feed(&decoder, &byte, 1U));

    decoder.error = false;
    decoder.done = true;
    assert_false(tron_stream_decoder_feed(&decoder, &byte, 1U));

    assert_false(tron_stream_decoder_is_done(NULL));
    reset_decoder(&decoder);
    assert_false(tron_stream_decoder_is_done(&decoder));
    decoder.done = true;
    decoder.error = true;
    assert_false(tron_stream_decoder_is_done(&decoder));
    decoder.error = false;
    assert_true(tron_stream_decoder_is_done(&decoder));

    reset_decoder(&decoder);
    decoder.done = false;
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
    assert_false(tron_stream_decoder_get_result(NULL, &result));
    assert_false(tron_stream_decoder_get_result(&decoder, NULL));

    decoder.done = true;
    decoder.result.has_fee_limit = true;
    decoder.result.fee_limit = 42;
    assert_true(tron_stream_decoder_get_result(&decoder, &result));
    assert_true(result.has_fee_limit);
    assert_int_equal(result.fee_limit, 42);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_helper_state_mutators),
        cmocka_unit_test(test_tron_current_ctx_and_push_frame_paths),
        cmocka_unit_test(test_tron_pop_finished_frames_and_consume_byte_paths),
        cmocka_unit_test(test_tron_varint_feed_paths),
        cmocka_unit_test(test_tron_length_action_maps_contexts),
        cmocka_unit_test(test_tron_handle_varint_value_paths),
        cmocka_unit_test(test_tron_start_capture_if_needed_paths),
        cmocka_unit_test(test_tron_enter_submessage_and_length_validation_paths),
        cmocka_unit_test(test_tron_process_length_paths),
        cmocka_unit_test(test_tron_process_byte_key_mode_paths),
        cmocka_unit_test(test_tron_process_byte_other_modes),
        cmocka_unit_test(test_public_decoder_api_paths),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
