#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "pb.h"
#include "core/Contract.pb.h"
#include "google/protobuf/any.pb.h"
#include "transaction_trigger_decode.h"

typedef struct {
    uint8_t bytes[1024];
    size_t len;
} test_pb_buffer_t;

typedef struct {
    uint8_t owner[32];
    size_t owner_len;
    uint8_t contract_address[32];
    size_t contract_address_len;
    uint8_t trigger_data[96];
    size_t trigger_data_len;
    uint8_t custom_data[48];
    size_t custom_data_len;
    uint64_t call_value;
    uint64_t call_token_value;
    uint64_t token_id;
    uint64_t fee_limit;
    uint32_t permission_id;
} decode_fixture_t;

typedef struct {
    test_pb_buffer_t trigger;
    test_pb_buffer_t any;
    test_pb_buffer_t contract;
    test_pb_buffer_t raw;
    test_pb_buffer_t tx;
} test_message_t;

typedef struct {
    uint8_t observed[128];
    size_t observed_len;
    size_t calls;
    size_t fail_at_offset;
} observer_ctx_t;

static const uint8_t test_trigger_type_url[] =
    "type.googleapis.com/protocol.TriggerSmartContract";

static size_t test_min_size(size_t a, size_t b) {
    return (a < b) ? a : b;
}

static void test_buffer_append_byte(test_pb_buffer_t *buffer, uint8_t byte) {
    assert_true(buffer->len < sizeof(buffer->bytes));
    buffer->bytes[buffer->len++] = byte;
}

static void test_buffer_append_varint(test_pb_buffer_t *buffer, uint64_t value) {
    do {
        uint8_t byte = (uint8_t) (value & 0x7FU);
        value >>= 7U;
        if (value != 0U) {
            byte |= 0x80U;
        }
        test_buffer_append_byte(buffer, byte);
    } while (value != 0U);
}

static void test_buffer_append_key(test_pb_buffer_t *buffer, uint32_t tag, pb_wire_type_t wire_type) {
    test_buffer_append_varint(buffer, ((uint64_t) tag << 3U) | (uint64_t) wire_type);
}

static void test_buffer_append_varint_field(test_pb_buffer_t *buffer, uint32_t tag, uint64_t value) {
    test_buffer_append_key(buffer, tag, PB_WT_VARINT);
    test_buffer_append_varint(buffer, value);
}

static void test_buffer_append_fixed32_field(test_pb_buffer_t *buffer,
                                             uint32_t tag,
                                             const uint8_t value[4]) {
    test_buffer_append_key(buffer, tag, PB_WT_32BIT);
    assert_true(buffer->len + 4U <= sizeof(buffer->bytes));
    memcpy(&buffer->bytes[buffer->len], value, 4U);
    buffer->len += 4U;
}

static void test_buffer_append_fixed64_field(test_pb_buffer_t *buffer,
                                             uint32_t tag,
                                             const uint8_t value[8]) {
    test_buffer_append_key(buffer, tag, PB_WT_64BIT);
    assert_true(buffer->len + 8U <= sizeof(buffer->bytes));
    memcpy(&buffer->bytes[buffer->len], value, 8U);
    buffer->len += 8U;
}

static void test_buffer_append_bytes_field(test_pb_buffer_t *buffer,
                                           uint32_t tag,
                                           const uint8_t *value,
                                           size_t value_len) {
    test_buffer_append_key(buffer, tag, PB_WT_STRING);
    test_buffer_append_varint(buffer, value_len);
    assert_true(buffer->len + value_len <= sizeof(buffer->bytes));
    if (value_len > 0U) {
        memcpy(&buffer->bytes[buffer->len], value, value_len);
        buffer->len += value_len;
    }
}

static void test_buffer_append_message_field(test_pb_buffer_t *buffer,
                                             uint32_t tag,
                                             const test_pb_buffer_t *submessage) {
    test_buffer_append_bytes_field(buffer, tag, submessage->bytes, submessage->len);
}

static void fill_sequence(uint8_t *buffer, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t) (seed + i);
    }
}

static void init_decode_fixture(decode_fixture_t *fixture,
                                size_t owner_len,
                                size_t contract_address_len,
                                size_t trigger_data_len,
                                size_t custom_data_len) {
    memset(fixture, 0, sizeof(*fixture));

    fixture->owner_len = owner_len;
    fixture->contract_address_len = contract_address_len;
    fixture->trigger_data_len = trigger_data_len;
    fixture->custom_data_len = custom_data_len;
    fixture->call_value = 123456U;
    fixture->call_token_value = 777U;
    fixture->token_id = 888U;
    fixture->fee_limit = 5000000U;
    fixture->permission_id = 9U;

    fill_sequence(fixture->owner, owner_len, 0x41U);
    fill_sequence(fixture->contract_address, contract_address_len, 0x61U);
    if (contract_address_len != 0U) {
        fixture->contract_address[0] = 0x41U;
    }
    fill_sequence(fixture->trigger_data, trigger_data_len, 0x10U);
    fill_sequence(fixture->custom_data, custom_data_len, 0x80U);
}

static test_pb_buffer_t build_trigger_message(const decode_fixture_t *fixture) {
    test_pb_buffer_t trigger = {0};

    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_owner_address_tag,
                                   fixture->owner,
                                   fixture->owner_len);
    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_contract_address_tag,
                                   fixture->contract_address,
                                   fixture->contract_address_len);
    test_buffer_append_varint_field(&trigger,
                                    protocol_TriggerSmartContract_call_value_tag,
                                    fixture->call_value);
    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_data_tag,
                                   fixture->trigger_data,
                                   fixture->trigger_data_len);
    test_buffer_append_varint_field(&trigger,
                                    protocol_TriggerSmartContract_call_token_value_tag,
                                    fixture->call_token_value);
    test_buffer_append_varint_field(&trigger,
                                    protocol_TriggerSmartContract_token_id_tag,
                                    fixture->token_id);

    return trigger;
}

static test_pb_buffer_t build_any_message_with_type_url(const test_pb_buffer_t *trigger,
                                                     const uint8_t *type_url,
                                                     size_t type_url_len,
                                                     bool include_type_url) {
    test_pb_buffer_t any = {0};

    if (include_type_url) {
        test_buffer_append_bytes_field(&any,
                                       google_protobuf_Any_type_url_tag,
                                       type_url,
                                       type_url_len);
    }
    test_buffer_append_bytes_field(&any, google_protobuf_Any_value_tag, trigger->bytes, trigger->len);

    return any;
}

static test_pb_buffer_t build_any_message(const test_pb_buffer_t *trigger) {
    return build_any_message_with_type_url(trigger,
                                           test_trigger_type_url,
                                           sizeof(test_trigger_type_url) - 1U,
                                           true);
}

static test_pb_buffer_t build_contract_message(const test_pb_buffer_t *any,
                                            protocol_Transaction_Contract_ContractType contract_type,
                                            uint32_t permission_id,
                                            bool parameter_first) {
    test_pb_buffer_t contract = {0};

    if (parameter_first) {
        test_buffer_append_message_field(&contract, protocol_Transaction_Contract_parameter_tag, any);
    }

    test_buffer_append_varint_field(&contract, protocol_Transaction_Contract_type_tag, contract_type);

    if (!parameter_first) {
        test_buffer_append_message_field(&contract, protocol_Transaction_Contract_parameter_tag, any);
    }

    test_buffer_append_varint_field(&contract,
                                    protocol_Transaction_Contract_Permission_id_tag,
                                    permission_id);

    return contract;
}

static test_pb_buffer_t build_raw_message(const test_pb_buffer_t *contract, const decode_fixture_t *fixture) {
    test_pb_buffer_t raw = {0};

    test_buffer_append_bytes_field(&raw,
                                   protocol_Transaction_raw_custom_data_tag,
                                   fixture->custom_data,
                                   fixture->custom_data_len);
    test_buffer_append_message_field(&raw, protocol_Transaction_raw_contract_tag, contract);
    test_buffer_append_varint_field(&raw, protocol_Transaction_raw_fee_limit_tag, fixture->fee_limit);

    return raw;
}

static test_pb_buffer_t build_transaction_message(const test_pb_buffer_t *raw) {
    test_pb_buffer_t tx = {0};

    test_buffer_append_message_field(&tx, protocol_Transaction_raw_data_tag, raw);

    return tx;
}

static void build_standard_message(const decode_fixture_t *fixture, test_message_t *message) {
    message->trigger = build_trigger_message(fixture);
    message->any = build_any_message(&message->trigger);
    message->contract = build_contract_message(
        &message->any,
        protocol_Transaction_Contract_ContractType_TriggerSmartContract,
        fixture->permission_id,
        false);
    message->raw = build_raw_message(&message->contract, fixture);
    message->tx = build_transaction_message(&message->raw);
}

static void assert_captured_field(bool has_value,
                                  const uint8_t *actual,
                                  size_t actual_len,
                                  const uint8_t *expected,
                                  size_t expected_len,
                                  size_t expected_cap) {
    const size_t capture_len = test_min_size(expected_len, expected_cap);

    assert_true(has_value);
    assert_int_equal(actual_len, capture_len);
    if (capture_len > 0U) {
        assert_memory_equal(actual, expected, capture_len);
    }
}

static void assert_result_matches_fixture(const tron_decode_result_t *result,
                                          const decode_fixture_t *fixture) {
    assert_true(result->has_contract_type);
    assert_int_equal(result->contract_type,
                     protocol_Transaction_Contract_ContractType_TriggerSmartContract);
    assert_true(result->has_permission_id);
    assert_int_equal(result->permission_id, fixture->permission_id);
    assert_true(result->has_fee_limit);
    assert_int_equal(result->fee_limit, fixture->fee_limit);
    assert_true(result->has_call_value);
    assert_int_equal(result->call_value, fixture->call_value);
    assert_true(result->has_call_token_value);
    assert_int_equal(result->call_token_value, fixture->call_token_value);
    assert_true(result->has_token_id);
    assert_int_equal(result->token_id, fixture->token_id);

    assert_captured_field(result->has_owner_address,
                          result->owner_address,
                          result->owner_address_len,
                          fixture->owner,
                          fixture->owner_len,
                          sizeof(result->owner_address));
    assert_captured_field(result->has_contract_address,
                          result->contract_address,
                          result->contract_address_len,
                          fixture->contract_address,
                          fixture->contract_address_len,
                          sizeof(result->contract_address));

    assert_true(result->has_data);
    assert_int_equal(result->data_len, fixture->trigger_data_len);
    assert_int_equal(result->data_prefix_len,
                     test_min_size(fixture->trigger_data_len, sizeof(result->data_prefix)));
    if (result->data_prefix_len > 0U) {
        assert_memory_equal(result->data_prefix, fixture->trigger_data, result->data_prefix_len);
    }

    assert_true(result->has_custom_data);
    assert_int_equal(result->custom_data_len, fixture->custom_data_len);
    assert_int_equal(result->custom_data_prefix_len,
                     test_min_size(fixture->custom_data_len, sizeof(result->custom_data_prefix)));
    if (result->custom_data_prefix_len > 0U) {
        assert_memory_equal(result->custom_data_prefix,
                            fixture->custom_data,
                            result->custom_data_prefix_len);
    }
}

static bool observer_collect(void *ctx,
                             const uint8_t *chunk,
                             size_t chunk_len,
                             size_t chunk_offset,
                             size_t total_len) {
    observer_ctx_t *observer = (observer_ctx_t *) ctx;

    assert_non_null(observer);
    assert_non_null(chunk);
    assert_true(chunk_len > 0U);
    assert_true(chunk_offset <= total_len);
    assert_true(chunk_len <= (total_len - chunk_offset));

    observer->calls++;
    if ((observer->fail_at_offset >= chunk_offset) &&
        (observer->fail_at_offset - chunk_offset < chunk_len)) {
        return false;
    }

    assert_true(observer->observed_len + chunk_len <= sizeof(observer->observed));
    memcpy(&observer->observed[observer->observed_len], chunk, chunk_len);
    observer->observed_len += chunk_len;
    return true;
}

static void feed_in_small_chunks(tron_stream_decoder_t *decoder, const uint8_t *data, size_t len) {
    static const size_t chunk_sizes[] = {1U, 2U, 5U, 3U, 8U};
    size_t offset = 0U;
    size_t chunk_index = 0U;

    while (offset < len) {
        size_t chunk_len = chunk_sizes[chunk_index % (sizeof(chunk_sizes) / sizeof(chunk_sizes[0]))];
        if (chunk_len > (len - offset)) {
            chunk_len = len - offset;
        }

        assert_true(tron_stream_decoder_feed(decoder, &data[offset], chunk_len));
        offset += chunk_len;
        chunk_index++;
    }
}

static void init_decoder_for_mode(tron_stream_decoder_t *decoder, bool raw_mode, size_t total_len) {
    if (raw_mode) {
        tron_stream_decoder_init_raw(decoder, total_len);
    } else {
        tron_stream_decoder_init(decoder, total_len);
    }
}

static void assert_invalid_decode(bool raw_mode, const uint8_t *data, size_t len) {
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    init_decoder_for_mode(&decoder, raw_mode, len);

    assert_false(tron_stream_decoder_feed(&decoder, data, len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
}

static void test_decode_transaction_in_chunks(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message;
    observer_ctx_t observer = {.fail_at_offset = SIZE_MAX};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    init_decode_fixture(&fixture, 21U, 21U, 80U, 40U);
    build_standard_message(&fixture, &message);

    tron_stream_decoder_init(&decoder, message.tx.len);
    tron_stream_decoder_set_trigger_data_observer(&decoder, observer_collect, &observer);

    feed_in_small_chunks(&decoder, message.tx.bytes, message.tx.len);

    assert_true(tron_stream_decoder_is_done(&decoder));
    assert_true(tron_stream_decoder_get_result(&decoder, &result));
    assert_result_matches_fixture(&result, &fixture);

    assert_true(observer.calls > 0U);
    assert_true(observer.calls <= fixture.trigger_data_len);
    assert_int_equal(observer.observed_len, fixture.trigger_data_len);
    assert_memory_equal(observer.observed, fixture.trigger_data, fixture.trigger_data_len);
}

static void test_custom_data_observer_receives_full_memo(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message;
    observer_ctx_t observer = {.fail_at_offset = SIZE_MAX};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    init_decode_fixture(&fixture, 21U, 21U, 80U, 40U);
    build_standard_message(&fixture, &message);
    tron_stream_decoder_init(&decoder, message.tx.len);
    tron_stream_decoder_set_custom_data_observer(&decoder, observer_collect, &observer);

    feed_in_small_chunks(&decoder, message.tx.bytes, message.tx.len);

    assert_true(tron_stream_decoder_get_result(&decoder, &result));
    assert_true(observer.calls > 0U);
    assert_int_equal(observer.observed_len, fixture.custom_data_len);
    assert_memory_equal(observer.observed, fixture.custom_data, fixture.custom_data_len);
}

static void test_decode_raw_message_in_single_buffer(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message;
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    init_decode_fixture(&fixture, 21U, 21U, 4U, 3U);
    fixture.call_value = 99U;
    fixture.call_token_value = 0U;
    fixture.token_id = 0U;
    fixture.fee_limit = 321U;
    fixture.permission_id = 2U;
    memcpy(fixture.custom_data, "TRX", 3U);
    fixture.custom_data_len = 3U;
    build_standard_message(&fixture, &message);

    tron_stream_decoder_init_raw(&decoder, message.raw.len);

    assert_true(tron_stream_decoder_feed(&decoder, message.raw.bytes, message.raw.len));
    assert_true(tron_stream_decoder_is_done(&decoder));
    assert_true(tron_stream_decoder_get_result(&decoder, &result));
    assert_result_matches_fixture(&result, &fixture);
}

static void test_rejects_oversized_address_fields(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message;
    init_decode_fixture(&fixture, 30U, 28U, 6U, 2U);
    build_standard_message(&fixture, &message);
    assert_invalid_decode(true, message.raw.bytes, message.raw.len);
}

static void test_observer_failure_marks_decoder_invalid(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message;
    observer_ctx_t observer = {.fail_at_offset = 0U};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    init_decode_fixture(&fixture, 21U, 21U, 4U, 1U);
    fixture.call_value = 7U;
    fixture.call_token_value = 0U;
    fixture.token_id = 0U;
    fixture.fee_limit = 100U;
    fixture.permission_id = 1U;
    build_standard_message(&fixture, &message);

    tron_stream_decoder_init(&decoder, message.tx.len);
    tron_stream_decoder_set_trigger_data_observer(&decoder, observer_collect, &observer);

    assert_false(tron_stream_decoder_feed(&decoder, message.tx.bytes, message.tx.len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
    assert_false(tron_stream_decoder_feed(&decoder, message.tx.bytes, 1U));
    assert_int_equal(observer.calls, 1);
    assert_int_equal(observer.observed_len, 0);
}

static void test_rejects_extra_bytes_after_declared_total(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message;
    uint8_t encoded[1024];
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    init_decode_fixture(&fixture, 21U, 21U, 4U, 2U);
    fixture.call_value = 1U;
    fixture.call_token_value = 2U;
    fixture.token_id = 3U;
    fixture.fee_limit = 5U;
    fixture.permission_id = 4U;
    build_standard_message(&fixture, &message);

    memcpy(encoded, message.tx.bytes, message.tx.len);
    encoded[message.tx.len] = 0x00U;

    tron_stream_decoder_init(&decoder, message.tx.len);

    assert_false(tron_stream_decoder_feed(&decoder, encoded, message.tx.len + 1U));
    assert_true(tron_stream_decoder_is_done(&decoder));
    assert_true(tron_stream_decoder_get_result(&decoder, &result));
    assert_result_matches_fixture(&result, &fixture);
}

static void test_rejects_unknown_fields_and_wrong_wire_types(void **state) {
    (void) state;

    const uint8_t top_level_signature[] = {0xAA, 0xBB};
    const uint8_t provider[] = {'d', 'e', 'm', 'o'};
    const uint8_t fixed32_value[4] = {0x44, 0x33, 0x22, 0x11};
    const uint8_t fixed64_value[8] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    decode_fixture_t fixture;
    test_message_t message = {0};
    tron_stream_decoder_t decoder;

    init_decode_fixture(&fixture, 21U, 21U, 4U, 2U);
    fixture.call_value = 42U;
    fixture.fee_limit = 999U;
    fixture.permission_id = 12U;

    test_buffer_append_bytes_field(&message.trigger,
                                   protocol_TriggerSmartContract_owner_address_tag,
                                   fixture.owner,
                                   fixture.owner_len);
    test_buffer_append_bytes_field(&message.trigger,
                                   protocol_TriggerSmartContract_contract_address_tag,
                                   fixture.contract_address,
                                   fixture.contract_address_len);
    test_buffer_append_fixed64_field(&message.trigger, 9U, fixed64_value);
    test_buffer_append_varint_field(&message.trigger,
                                    protocol_TriggerSmartContract_call_value_tag,
                                    fixture.call_value);
    test_buffer_append_bytes_field(&message.trigger,
                                   protocol_TriggerSmartContract_data_tag,
                                   fixture.trigger_data,
                                   fixture.trigger_data_len);
    test_buffer_append_varint_field(&message.trigger,
                                    protocol_TriggerSmartContract_call_token_value_tag,
                                    fixture.call_token_value);
    test_buffer_append_varint_field(&message.trigger,
                                    protocol_TriggerSmartContract_token_id_tag,
                                    fixture.token_id);

    message.any = build_any_message(&message.trigger);

    test_buffer_append_varint_field(&message.contract,
                                    protocol_Transaction_Contract_type_tag,
                                    protocol_Transaction_Contract_ContractType_TriggerSmartContract);
    test_buffer_append_bytes_field(&message.contract, 3U, provider, sizeof(provider));
    test_buffer_append_message_field(&message.contract,
                                     protocol_Transaction_Contract_parameter_tag,
                                     &message.any);
    test_buffer_append_varint_field(&message.contract,
                                    protocol_Transaction_Contract_Permission_id_tag,
                                    fixture.permission_id);

    test_buffer_append_bytes_field(&message.raw,
                                   protocol_Transaction_raw_custom_data_tag,
                                   fixture.custom_data,
                                   fixture.custom_data_len);
    test_buffer_append_fixed32_field(&message.raw, 12U, fixed32_value);
    test_buffer_append_message_field(&message.raw, protocol_Transaction_raw_contract_tag, &message.contract);
    test_buffer_append_varint_field(&message.raw, protocol_Transaction_raw_fee_limit_tag, fixture.fee_limit);

    test_buffer_append_bytes_field(&message.tx,
                                   protocol_Transaction_signature_tag,
                                   top_level_signature,
                                   0U);
    test_buffer_append_message_field(&message.tx, protocol_Transaction_raw_data_tag, &message.raw);

    (void) decoder;
    assert_invalid_decode(false, message.tx.bytes, message.tx.len);
}

static void test_rejects_hidden_fee_bearing_fields(void **state) {
    (void) state;

    static const uint32_t raw_forbidden_tags[] = {9U, 12U};
    static const uint32_t contract_forbidden_tags[] = {
        protocol_Transaction_Contract_provider_tag,
        protocol_Transaction_Contract_ContractName_tag,
    };
    static const uint8_t forbidden_value[] = {0xAAU};
    decode_fixture_t fixture;

    init_decode_fixture(&fixture, 21U, 21U, 4U, 0U);
    for (size_t i = 0U; i < sizeof(raw_forbidden_tags) / sizeof(raw_forbidden_tags[0]); i++) {
        test_message_t message = {0};

        message.trigger = build_trigger_message(&fixture);
        message.any = build_any_message(&message.trigger);
        message.contract = build_contract_message(
            &message.any,
            protocol_Transaction_Contract_ContractType_TriggerSmartContract,
            fixture.permission_id,
            false);
        test_buffer_append_bytes_field(&message.raw,
                                       raw_forbidden_tags[i],
                                       forbidden_value,
                                       sizeof(forbidden_value));
        test_buffer_append_message_field(&message.raw,
                                         protocol_Transaction_raw_contract_tag,
                                         &message.contract);
        assert_invalid_decode(true, message.raw.bytes, message.raw.len);
    }

    for (size_t i = 0U;
         i < sizeof(contract_forbidden_tags) / sizeof(contract_forbidden_tags[0]);
         i++) {
        test_message_t message = {0};

        message.trigger = build_trigger_message(&fixture);
        message.any = build_any_message(&message.trigger);
        test_buffer_append_varint_field(
            &message.contract,
            protocol_Transaction_Contract_type_tag,
            protocol_Transaction_Contract_ContractType_TriggerSmartContract);
        test_buffer_append_bytes_field(&message.contract,
                                       contract_forbidden_tags[i],
                                       forbidden_value,
                                       sizeof(forbidden_value));
        test_buffer_append_message_field(&message.contract,
                                         protocol_Transaction_Contract_parameter_tag,
                                         &message.any);
        message.raw = build_raw_message(&message.contract, &fixture);
        assert_invalid_decode(true, message.raw.bytes, message.raw.len);
    }
}

static void test_handles_zero_length_memo_and_zero_length_decoder(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message;
    const uint8_t byte = 0x00U;
    tron_stream_decoder_t decoder;
    tron_stream_decoder_t empty_decoder;
    tron_stream_decoder_t empty_raw_decoder;
    tron_decode_result_t result;

    init_decode_fixture(&fixture, 21U, 21U, 4U, 0U);
    fixture.call_value = 0U;
    fixture.call_token_value = 0U;
    fixture.token_id = 0U;
    fixture.fee_limit = 0U;
    fixture.permission_id = 0U;
    build_standard_message(&fixture, &message);

    tron_stream_decoder_init(&decoder, message.tx.len);
    assert_true(tron_stream_decoder_feed(&decoder, message.tx.bytes, message.tx.len));
    assert_true(tron_stream_decoder_get_result(&decoder, &result));
    assert_result_matches_fixture(&result, &fixture);

    tron_stream_decoder_init(&empty_decoder, 0U);
    assert_true(tron_stream_decoder_is_done(&empty_decoder));
    assert_false(tron_stream_decoder_get_result(&empty_decoder, &result));
    assert_false(tron_stream_decoder_feed(&empty_decoder, &byte, 0U));

    tron_stream_decoder_init_raw(&empty_raw_decoder, 0U);
    assert_true(tron_stream_decoder_is_done(&empty_raw_decoder));
    assert_false(tron_stream_decoder_get_result(&empty_raw_decoder, &result));
}

static void test_zero_length_feed_is_noop_before_completion(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message;
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    init_decode_fixture(&fixture, 21U, 21U, 4U, 1U);
    build_standard_message(&fixture, &message);

    tron_stream_decoder_init_raw(&decoder, message.raw.len);

    assert_true(tron_stream_decoder_feed(&decoder, message.raw.bytes, 0U));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));

    assert_true(tron_stream_decoder_feed(&decoder, message.raw.bytes, message.raw.len));
    assert_true(tron_stream_decoder_is_done(&decoder));
}

static void test_api_argument_guards(void **state) {
    (void) state;

    const uint8_t byte = 0x00U;
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    tron_stream_decoder_init(&decoder, 1U);

    tron_stream_decoder_set_trigger_data_observer(NULL, observer_collect, NULL);

    assert_false(tron_stream_decoder_feed(NULL, &byte, 1U));
    assert_false(tron_stream_decoder_feed(&decoder, NULL, 1U));
    assert_false(tron_stream_decoder_is_done(NULL));
    assert_false(tron_stream_decoder_get_result(NULL, &result));
    assert_false(tron_stream_decoder_get_result(&decoder, NULL));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
}

static void test_rejects_invalid_wire_type_and_overlong_varints(void **state) {
    (void) state;

    const uint8_t invalid_zero_tag[] = {0x00U};
    const uint8_t invalid_large_tag[] = {0x88U, 0x80U, 0x80U, 0x80U, 0x80U, 0x01U};
    const uint8_t invalid_wire[] = {0x0EU};
    const uint8_t invalid_length[] = {
        0x0AU,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
    };
    const uint8_t invalid_value[] = {
        0x90U, 0x01U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
    };
    const uint8_t invalid_key[] = {
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
    };

    assert_invalid_decode(false, invalid_zero_tag, sizeof(invalid_zero_tag));
    assert_invalid_decode(false, invalid_large_tag, sizeof(invalid_large_tag));
    assert_invalid_decode(false, invalid_wire, sizeof(invalid_wire));
    assert_invalid_decode(false, invalid_length, sizeof(invalid_length));
    assert_invalid_decode(true, invalid_value, sizeof(invalid_value));
    assert_invalid_decode(false, invalid_key, sizeof(invalid_key));
}

static void test_rejects_non_trigger_contract_type(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message = {0};

    init_decode_fixture(&fixture, 21U, 21U, 4U, 1U);
    message.trigger = build_trigger_message(&fixture);
    message.any = build_any_message(&message.trigger);
    message.contract = build_contract_message(&message.any,
                                              protocol_Transaction_Contract_ContractType_TransferContract,
                                              1U,
                                              true);
    message.raw = build_raw_message(&message.contract, &fixture);

    assert_invalid_decode(true, message.raw.bytes, message.raw.len);
}

static void test_rejects_trigger_parameter_before_contract_type(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message = {0};

    init_decode_fixture(&fixture, 21U, 21U, 4U, 1U);
    message.trigger = build_trigger_message(&fixture);
    message.any = build_any_message(&message.trigger);
    message.contract = build_contract_message(&message.any,
                                              protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                                              1U,
                                              true);
    message.raw = build_raw_message(&message.contract, &fixture);

    assert_invalid_decode(true, message.raw.bytes, message.raw.len);
}

static void test_rejects_multiple_contracts(void **state) {
    (void) state;

    decode_fixture_t fixture1;
    decode_fixture_t fixture2;
    test_message_t message1;
    test_message_t message2;
    test_pb_buffer_t raw = {0};

    init_decode_fixture(&fixture1, 21U, 21U, 4U, 1U);
    fixture1.call_value = 100U;
    fixture1.call_token_value = 1U;
    fixture1.token_id = 2U;
    fixture1.permission_id = 7U;
    build_standard_message(&fixture1, &message1);

    init_decode_fixture(&fixture2, 21U, 21U, 4U, 1U);
    fixture2.owner[1] = 0x02U;
    fixture2.contract_address[1] = 0x22U;
    fixture2.call_value = 200U;
    fixture2.call_token_value = 3U;
    fixture2.token_id = 4U;
    fixture2.permission_id = 8U;
    build_standard_message(&fixture2, &message2);

    test_buffer_append_bytes_field(&raw,
                                   protocol_Transaction_raw_custom_data_tag,
                                   fixture1.custom_data,
                                   fixture1.custom_data_len);
    test_buffer_append_message_field(&raw, protocol_Transaction_raw_contract_tag, &message1.contract);
    test_buffer_append_message_field(&raw, protocol_Transaction_raw_contract_tag, &message2.contract);
    test_buffer_append_varint_field(&raw, protocol_Transaction_raw_fee_limit_tag, 999U);

    assert_invalid_decode(true, raw.bytes, raw.len);
}

static void test_rejects_data_before_addresses(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message = {0};

    init_decode_fixture(&fixture, 21U, 21U, 4U, 1U);

    test_buffer_append_bytes_field(&message.trigger,
                                   protocol_TriggerSmartContract_data_tag,
                                   fixture.trigger_data,
                                   fixture.trigger_data_len);
    test_buffer_append_bytes_field(&message.trigger,
                                   protocol_TriggerSmartContract_owner_address_tag,
                                   fixture.owner,
                                   fixture.owner_len);
    test_buffer_append_bytes_field(&message.trigger,
                                   protocol_TriggerSmartContract_contract_address_tag,
                                   fixture.contract_address,
                                   fixture.contract_address_len);
    test_buffer_append_varint_field(&message.trigger,
                                    protocol_TriggerSmartContract_call_value_tag,
                                    1U);

    message.any = build_any_message(&message.trigger);
    message.contract = build_contract_message(&message.any,
                                              protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                                              1U,
                                              false);
    message.raw = build_raw_message(&message.contract, &fixture);

    assert_invalid_decode(true, message.raw.bytes, message.raw.len);
}

static void test_rejects_duplicate_contract_parameter(void **state) {
    (void) state;

    decode_fixture_t fixture1;
    decode_fixture_t fixture2;
    test_pb_buffer_t contract = {0};
    test_pb_buffer_t raw = {0};
    test_message_t message1;
    test_message_t message2;

    init_decode_fixture(&fixture1, 21U, 21U, 4U, 1U);
    build_standard_message(&fixture1, &message1);

    init_decode_fixture(&fixture2, 21U, 21U, 4U, 1U);
    fixture2.owner[1] = 0x02U;
    fixture2.contract_address[1] = 0x22U;
    build_standard_message(&fixture2, &message2);

    test_buffer_append_varint_field(&contract,
                                    protocol_Transaction_Contract_type_tag,
                                    protocol_Transaction_Contract_ContractType_TriggerSmartContract);
    test_buffer_append_message_field(&contract,
                                     protocol_Transaction_Contract_parameter_tag,
                                     &message1.any);
    test_buffer_append_message_field(&contract,
                                     protocol_Transaction_Contract_parameter_tag,
                                     &message2.any);
    test_buffer_append_bytes_field(&raw,
                                   protocol_Transaction_raw_custom_data_tag,
                                   fixture1.custom_data,
                                   fixture1.custom_data_len);
    test_buffer_append_message_field(&raw, protocol_Transaction_raw_contract_tag, &contract);
    test_buffer_append_varint_field(&raw, protocol_Transaction_raw_fee_limit_tag, 7U);

    assert_invalid_decode(true, raw.bytes, raw.len);
}

static void test_rejects_duplicate_any_value(void **state) {
    (void) state;

    decode_fixture_t fixture1;
    decode_fixture_t fixture2;
    test_pb_buffer_t any = {0};
    test_pb_buffer_t contract;
    test_pb_buffer_t raw;
    test_message_t message1;
    test_message_t message2;

    init_decode_fixture(&fixture1, 21U, 21U, 4U, 1U);
    build_standard_message(&fixture1, &message1);

    init_decode_fixture(&fixture2, 21U, 21U, 4U, 1U);
    fixture2.owner[1] = 0x02U;
    fixture2.contract_address[1] = 0x22U;
    build_standard_message(&fixture2, &message2);

    test_buffer_append_bytes_field(&any,
                                   google_protobuf_Any_type_url_tag,
                                   test_trigger_type_url,
                                   sizeof(test_trigger_type_url) - 1U);
    test_buffer_append_bytes_field(&any, google_protobuf_Any_value_tag, message1.trigger.bytes, message1.trigger.len);
    test_buffer_append_bytes_field(&any, google_protobuf_Any_value_tag, message2.trigger.bytes, message2.trigger.len);
    contract = build_contract_message(&any,
                                      protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                                      1U,
                                      false);
    raw = build_raw_message(&contract, &fixture1);

    assert_invalid_decode(true, raw.bytes, raw.len);
}

static void test_rejects_missing_any_type_url(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message = {0};

    init_decode_fixture(&fixture, 21U, 21U, 4U, 1U);
    message.trigger = build_trigger_message(&fixture);
    message.any = build_any_message_with_type_url(&message.trigger, NULL, 0U, false);
    message.contract = build_contract_message(&message.any,
                                              protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                                              1U,
                                              false);
    message.raw = build_raw_message(&message.contract, &fixture);

    assert_invalid_decode(true, message.raw.bytes, message.raw.len);
}

static void test_rejects_invalid_any_type_url(void **state) {
    (void) state;

    const uint8_t invalid_type_url[] = "type.googleapis.com/protocol.TransferContract";
    decode_fixture_t fixture;
    test_message_t message = {0};

    init_decode_fixture(&fixture, 21U, 21U, 4U, 1U);
    message.trigger = build_trigger_message(&fixture);
    message.any = build_any_message_with_type_url(&message.trigger,
                                                  invalid_type_url,
                                                  sizeof(invalid_type_url) - 1U,
                                                  true);
    message.contract = build_contract_message(&message.any,
                                              protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                                              1U,
                                              false);
    message.raw = build_raw_message(&message.contract, &fixture);

    assert_invalid_decode(true, message.raw.bytes, message.raw.len);
}

static void test_rejects_duplicate_any_type_url(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_pb_buffer_t any = {0};
    test_pb_buffer_t contract;
    test_pb_buffer_t raw;
    test_message_t message;

    init_decode_fixture(&fixture, 21U, 21U, 4U, 1U);
    build_standard_message(&fixture, &message);

    test_buffer_append_bytes_field(&any,
                                   google_protobuf_Any_type_url_tag,
                                   test_trigger_type_url,
                                   sizeof(test_trigger_type_url) - 1U);
    test_buffer_append_bytes_field(&any,
                                   google_protobuf_Any_type_url_tag,
                                   test_trigger_type_url,
                                   sizeof(test_trigger_type_url) - 1U);
    test_buffer_append_bytes_field(&any, google_protobuf_Any_value_tag, message.trigger.bytes, message.trigger.len);
    contract = build_contract_message(&any,
                                      protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                                      1U,
                                      false);
    raw = build_raw_message(&contract, &fixture);

    assert_invalid_decode(true, raw.bytes, raw.len);
}

static void test_rejects_duplicate_trigger_singleton_field(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message = {0};
    uint8_t owner2[21];

    init_decode_fixture(&fixture, 21U, 21U, 4U, 1U);
    memcpy(owner2, fixture.owner, sizeof(owner2));
    owner2[1] = 0x02U;

    test_buffer_append_bytes_field(&message.trigger,
                                   protocol_TriggerSmartContract_owner_address_tag,
                                   fixture.owner,
                                   fixture.owner_len);
    test_buffer_append_bytes_field(&message.trigger,
                                   protocol_TriggerSmartContract_contract_address_tag,
                                   fixture.contract_address,
                                   fixture.contract_address_len);
    test_buffer_append_bytes_field(&message.trigger,
                                   protocol_TriggerSmartContract_data_tag,
                                   fixture.trigger_data,
                                   fixture.trigger_data_len);
    test_buffer_append_bytes_field(&message.trigger,
                                   protocol_TriggerSmartContract_owner_address_tag,
                                   owner2,
                                   sizeof(owner2));
    test_buffer_append_varint_field(&message.trigger,
                                    protocol_TriggerSmartContract_call_value_tag,
                                    1U);

    message.any = build_any_message(&message.trigger);
    message.contract = build_contract_message(&message.any,
                                              protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                                              1U,
                                              false);
    message.raw = build_raw_message(&message.contract, &fixture);

    assert_invalid_decode(true, message.raw.bytes, message.raw.len);
}

static void test_rejects_duplicate_trigger_numeric_field(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message = {0};

    init_decode_fixture(&fixture, 21U, 21U, 4U, 1U);

    test_buffer_append_bytes_field(&message.trigger,
                                   protocol_TriggerSmartContract_owner_address_tag,
                                   fixture.owner,
                                   fixture.owner_len);
    test_buffer_append_bytes_field(&message.trigger,
                                   protocol_TriggerSmartContract_contract_address_tag,
                                   fixture.contract_address,
                                   fixture.contract_address_len);
    test_buffer_append_varint_field(&message.trigger,
                                    protocol_TriggerSmartContract_call_value_tag,
                                    1U);
    test_buffer_append_bytes_field(&message.trigger,
                                   protocol_TriggerSmartContract_data_tag,
                                   fixture.trigger_data,
                                   fixture.trigger_data_len);
    test_buffer_append_varint_field(&message.trigger,
                                    protocol_TriggerSmartContract_call_value_tag,
                                    2U);

    message.any = build_any_message(&message.trigger);
    message.contract = build_contract_message(&message.any,
                                              protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                                              1U,
                                              false);
    message.raw = build_raw_message(&message.contract, &fixture);

    assert_invalid_decode(true, message.raw.bytes, message.raw.len);
}

static void test_rejects_duplicate_contract_numeric_fields(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message;
    test_pb_buffer_t contract = {0};
    test_pb_buffer_t raw = {0};

    init_decode_fixture(&fixture, 21U, 21U, 4U, 1U);
    build_standard_message(&fixture, &message);

    test_buffer_append_varint_field(&contract,
                                    protocol_Transaction_Contract_type_tag,
                                    protocol_Transaction_Contract_ContractType_TriggerSmartContract);
    test_buffer_append_varint_field(&contract,
                                    protocol_Transaction_Contract_type_tag,
                                    protocol_Transaction_Contract_ContractType_TriggerSmartContract);
    test_buffer_append_message_field(&contract,
                                     protocol_Transaction_Contract_parameter_tag,
                                     &message.any);
    test_buffer_append_varint_field(&contract,
                                    protocol_Transaction_Contract_Permission_id_tag,
                                    1U);
    test_buffer_append_varint_field(&contract,
                                    protocol_Transaction_Contract_Permission_id_tag,
                                    2U);

    test_buffer_append_bytes_field(&raw,
                                   protocol_Transaction_raw_custom_data_tag,
                                   fixture.custom_data,
                                   fixture.custom_data_len);
    test_buffer_append_message_field(&raw, protocol_Transaction_raw_contract_tag, &contract);
    test_buffer_append_varint_field(&raw, protocol_Transaction_raw_fee_limit_tag, fixture.fee_limit);

    assert_invalid_decode(true, raw.bytes, raw.len);
}

static void test_rejects_duplicate_raw_fields(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message;
    test_pb_buffer_t raw = {0};

    init_decode_fixture(&fixture, 21U, 21U, 4U, 2U);
    build_standard_message(&fixture, &message);

    test_buffer_append_bytes_field(&raw,
                                   protocol_Transaction_raw_custom_data_tag,
                                   fixture.custom_data,
                                   fixture.custom_data_len);
    test_buffer_append_bytes_field(&raw,
                                   protocol_Transaction_raw_custom_data_tag,
                                   fixture.custom_data,
                                   fixture.custom_data_len);
    test_buffer_append_message_field(&raw, protocol_Transaction_raw_contract_tag, &message.contract);
    test_buffer_append_varint_field(&raw, protocol_Transaction_raw_fee_limit_tag, 1U);
    test_buffer_append_varint_field(&raw, protocol_Transaction_raw_fee_limit_tag, 2U);

    assert_invalid_decode(true, raw.bytes, raw.len);
}

static void test_rejects_length_exceeding_remaining_bytes(void **state) {
    (void) state;

    test_pb_buffer_t raw = {0};

    test_buffer_append_key(&raw, protocol_Transaction_raw_custom_data_tag, PB_WT_STRING);
    test_buffer_append_varint(&raw, 3U);
    test_buffer_append_byte(&raw, 0xAAU);

    assert_invalid_decode(true, raw.bytes, raw.len);
}

static void test_truncated_terminal_varint_is_not_marked_done(void **state) {
    (void) state;

    const uint8_t raw[] = {
        0x90U, 0x01U,
        0x80U,
    };
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    tron_stream_decoder_init_raw(&decoder, sizeof(raw));

    assert_true(tron_stream_decoder_feed(&decoder, raw, sizeof(raw)));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
}

static void test_rejects_out_of_range_numeric_fields(void **state) {
    (void) state;

    decode_fixture_t fixture;
    test_message_t message;

    init_decode_fixture(&fixture, 21U, 21U, 4U, 1U);
    fixture.call_value = UINT64_MAX;
    build_standard_message(&fixture, &message);
    assert_invalid_decode(true, message.raw.bytes, message.raw.len);

    init_decode_fixture(&fixture, 21U, 21U, 4U, 1U);
    fixture.permission_id = 300U;
    build_standard_message(&fixture, &message);
    assert_invalid_decode(true, message.raw.bytes, message.raw.len);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_decode_transaction_in_chunks),
        cmocka_unit_test(test_custom_data_observer_receives_full_memo),
        cmocka_unit_test(test_decode_raw_message_in_single_buffer),
        cmocka_unit_test(test_rejects_oversized_address_fields),
        cmocka_unit_test(test_observer_failure_marks_decoder_invalid),
        cmocka_unit_test(test_rejects_extra_bytes_after_declared_total),
        cmocka_unit_test(test_rejects_unknown_fields_and_wrong_wire_types),
        cmocka_unit_test(test_rejects_hidden_fee_bearing_fields),
        cmocka_unit_test(test_handles_zero_length_memo_and_zero_length_decoder),
        cmocka_unit_test(test_zero_length_feed_is_noop_before_completion),
        cmocka_unit_test(test_api_argument_guards),
        cmocka_unit_test(test_rejects_invalid_wire_type_and_overlong_varints),
        cmocka_unit_test(test_rejects_non_trigger_contract_type),
        cmocka_unit_test(test_rejects_trigger_parameter_before_contract_type),
        cmocka_unit_test(test_rejects_multiple_contracts),
        cmocka_unit_test(test_rejects_data_before_addresses),
        cmocka_unit_test(test_rejects_duplicate_contract_parameter),
        cmocka_unit_test(test_rejects_duplicate_any_value),
        cmocka_unit_test(test_rejects_missing_any_type_url),
        cmocka_unit_test(test_rejects_invalid_any_type_url),
        cmocka_unit_test(test_rejects_duplicate_any_type_url),
        cmocka_unit_test(test_rejects_duplicate_trigger_singleton_field),
        cmocka_unit_test(test_rejects_duplicate_trigger_numeric_field),
        cmocka_unit_test(test_rejects_duplicate_contract_numeric_fields),
        cmocka_unit_test(test_rejects_duplicate_raw_fields),
        cmocka_unit_test(test_rejects_length_exceeding_remaining_bytes),
        cmocka_unit_test(test_truncated_terminal_varint_is_not_marked_done),
        cmocka_unit_test(test_rejects_out_of_range_numeric_fields),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
