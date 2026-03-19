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
} test_buffer_t;

typedef struct {
    uint8_t observed[128];
    size_t observed_len;
    size_t calls;
    size_t fail_at_offset;
} observer_ctx_t;

static const uint8_t test_trigger_type_url[] =
    "type.googleapis.com/protocol.TriggerSmartContract";

static void test_buffer_append_byte(test_buffer_t *buffer, uint8_t byte) {
    assert_true(buffer->len < sizeof(buffer->bytes));
    buffer->bytes[buffer->len++] = byte;
}

static void test_buffer_append_varint(test_buffer_t *buffer, uint64_t value) {
    do {
        uint8_t byte = (uint8_t) (value & 0x7FU);
        value >>= 7U;
        if (value != 0U) {
            byte |= 0x80U;
        }
        test_buffer_append_byte(buffer, byte);
    } while (value != 0U);
}

static void test_buffer_append_key(test_buffer_t *buffer, uint32_t tag, pb_wire_type_t wire_type) {
    test_buffer_append_varint(buffer, ((uint64_t) tag << 3U) | (uint64_t) wire_type);
}

static void test_buffer_append_varint_field(test_buffer_t *buffer, uint32_t tag, uint64_t value) {
    test_buffer_append_key(buffer, tag, PB_WT_VARINT);
    test_buffer_append_varint(buffer, value);
}

static void test_buffer_append_fixed32_field(test_buffer_t *buffer,
                                             uint32_t tag,
                                             const uint8_t value[4]) {
    test_buffer_append_key(buffer, tag, PB_WT_32BIT);
    assert_true(buffer->len + 4U <= sizeof(buffer->bytes));
    memcpy(&buffer->bytes[buffer->len], value, 4U);
    buffer->len += 4U;
}

static void test_buffer_append_fixed64_field(test_buffer_t *buffer,
                                             uint32_t tag,
                                             const uint8_t value[8]) {
    test_buffer_append_key(buffer, tag, PB_WT_64BIT);
    assert_true(buffer->len + 8U <= sizeof(buffer->bytes));
    memcpy(&buffer->bytes[buffer->len], value, 8U);
    buffer->len += 8U;
}

static void test_buffer_append_bytes_field(test_buffer_t *buffer,
                                           uint32_t tag,
                                           const uint8_t *value,
                                           size_t value_len) {
    test_buffer_append_key(buffer, tag, PB_WT_STRING);
    test_buffer_append_varint(buffer, value_len);
    assert_true(buffer->len + value_len <= sizeof(buffer->bytes));
    memcpy(&buffer->bytes[buffer->len], value, value_len);
    buffer->len += value_len;
}

static void test_buffer_append_message_field(test_buffer_t *buffer,
                                             uint32_t tag,
                                             const test_buffer_t *submessage) {
    test_buffer_append_bytes_field(buffer, tag, submessage->bytes, submessage->len);
}

static void fill_sequence(uint8_t *buffer, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t) (seed + i);
    }
}

static test_buffer_t build_trigger_message(const uint8_t *owner,
                                           size_t owner_len,
                                           const uint8_t *contract,
                                           size_t contract_len,
                                           uint64_t call_value,
                                           const uint8_t *data,
                                           size_t data_len,
                                           uint64_t call_token_value,
                                           uint64_t token_id) {
    test_buffer_t trigger = {0};

    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_owner_address_tag,
                                   owner,
                                   owner_len);
    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_contract_address_tag,
                                   contract,
                                   contract_len);
    test_buffer_append_varint_field(&trigger,
                                    protocol_TriggerSmartContract_call_value_tag,
                                    call_value);
    test_buffer_append_bytes_field(&trigger, protocol_TriggerSmartContract_data_tag, data, data_len);
    test_buffer_append_varint_field(&trigger,
                                    protocol_TriggerSmartContract_call_token_value_tag,
                                    call_token_value);
    test_buffer_append_varint_field(&trigger, protocol_TriggerSmartContract_token_id_tag, token_id);

    return trigger;
}

static test_buffer_t build_any_message(const test_buffer_t *trigger) {
    test_buffer_t any = {0};

    test_buffer_append_bytes_field(&any,
                                   google_protobuf_Any_type_url_tag,
                                   test_trigger_type_url,
                                   sizeof(test_trigger_type_url) - 1U);
    test_buffer_append_bytes_field(&any, google_protobuf_Any_value_tag, trigger->bytes, trigger->len);

    return any;
}

static test_buffer_t build_contract_message(const test_buffer_t *any,
                                            protocol_Transaction_Contract_ContractType contract_type,
                                            uint32_t permission_id) {
    test_buffer_t contract = {0};

    test_buffer_append_varint_field(&contract, protocol_Transaction_Contract_type_tag, contract_type);
    test_buffer_append_message_field(&contract, protocol_Transaction_Contract_parameter_tag, any);
    test_buffer_append_varint_field(&contract,
                                    protocol_Transaction_Contract_Permission_id_tag,
                                    permission_id);

    return contract;
}

static test_buffer_t build_contract_message_parameter_first(
    const test_buffer_t *any,
    protocol_Transaction_Contract_ContractType contract_type,
    uint32_t permission_id) {
    test_buffer_t contract = {0};

    test_buffer_append_message_field(&contract, protocol_Transaction_Contract_parameter_tag, any);
    test_buffer_append_varint_field(&contract, protocol_Transaction_Contract_type_tag, contract_type);
    test_buffer_append_varint_field(&contract,
                                    protocol_Transaction_Contract_Permission_id_tag,
                                    permission_id);

    return contract;
}

static test_buffer_t build_raw_message(const test_buffer_t *contract,
                                       uint64_t fee_limit,
                                       const uint8_t *custom_data,
                                       size_t custom_data_len) {
    test_buffer_t raw = {0};

    test_buffer_append_bytes_field(&raw,
                                   protocol_Transaction_raw_custom_data_tag,
                                   custom_data,
                                   custom_data_len);
    test_buffer_append_message_field(&raw, protocol_Transaction_raw_contract_tag, contract);
    test_buffer_append_varint_field(&raw, protocol_Transaction_raw_fee_limit_tag, fee_limit);

    return raw;
}

static test_buffer_t build_transaction_message(const test_buffer_t *raw) {
    test_buffer_t tx = {0};

    test_buffer_append_message_field(&tx, protocol_Transaction_raw_data_tag, raw);

    return tx;
}

static bool observer_collect(void *ctx,
                             const uint8_t *chunk,
                             size_t chunk_len,
                             size_t chunk_offset,
                             size_t total_len) {
    observer_ctx_t *observer = (observer_ctx_t *) ctx;

    assert_non_null(observer);
    assert_non_null(chunk);
    assert_int_equal(chunk_len, 1);
    assert_true(chunk_offset < total_len);

    observer->calls++;
    if (chunk_offset == observer->fail_at_offset) {
        return false;
    }

    assert_true(observer->observed_len + chunk_len <= sizeof(observer->observed));
    memcpy(&observer->observed[observer->observed_len], chunk, chunk_len);
    observer->observed_len += chunk_len;
    return true;
}

static void feed_in_small_chunks(tron_stream_decoder_t *decoder,
                                 const uint8_t *data,
                                 size_t len) {
    static const size_t chunk_sizes[] = {1U, 2U, 5U, 3U, 8U};
    size_t offset = 0;
    size_t chunk_index = 0;

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

static void test_decode_transaction_in_chunks(void **state) {
    (void) state;

    uint8_t owner[21];
    uint8_t contract_address[21];
    uint8_t trigger_data[80];
    uint8_t custom_data[40];
    observer_ctx_t observer = {.fail_at_offset = SIZE_MAX};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    fill_sequence(owner, sizeof(owner), 0x41U);
    fill_sequence(contract_address, sizeof(contract_address), 0x61U);
    fill_sequence(trigger_data, sizeof(trigger_data), 0x10U);
    fill_sequence(custom_data, sizeof(custom_data), 0x80U);

    const test_buffer_t trigger = build_trigger_message(owner,
                                                        sizeof(owner),
                                                        contract_address,
                                                        sizeof(contract_address),
                                                        123456U,
                                                        trigger_data,
                                                        sizeof(trigger_data),
                                                        777U,
                                                        888U);
    const test_buffer_t any = build_any_message(&trigger);
    const test_buffer_t contract =
        build_contract_message(&any,
                               protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                               9U);
    const test_buffer_t raw = build_raw_message(&contract, 5000000U, custom_data, sizeof(custom_data));
    const test_buffer_t tx = build_transaction_message(&raw);

    tron_stream_decoder_init(&decoder, tx.len);
    tron_stream_decoder_set_trigger_data_observer(&decoder, observer_collect, &observer);

    feed_in_small_chunks(&decoder, tx.bytes, tx.len);

    assert_true(tron_stream_decoder_is_done(&decoder));
    assert_true(tron_stream_decoder_get_result(&decoder, &result));

    assert_true(result.has_contract_type);
    assert_int_equal(result.contract_type,
                     protocol_Transaction_Contract_ContractType_TriggerSmartContract);
    assert_true(result.has_permission_id);
    assert_int_equal(result.permission_id, 9);
    assert_true(result.has_fee_limit);
    assert_int_equal(result.fee_limit, 5000000);
    assert_true(result.has_call_value);
    assert_int_equal(result.call_value, 123456);
    assert_true(result.has_call_token_value);
    assert_int_equal(result.call_token_value, 777);
    assert_true(result.has_token_id);
    assert_int_equal(result.token_id, 888);

    assert_true(result.has_owner_address);
    assert_int_equal(result.owner_address_len, sizeof(owner));
    assert_memory_equal(result.owner_address, owner, sizeof(owner));

    assert_true(result.has_contract_address);
    assert_int_equal(result.contract_address_len, sizeof(contract_address));
    assert_memory_equal(result.contract_address, contract_address, sizeof(contract_address));

    assert_true(result.has_data);
    assert_int_equal(result.data_len, sizeof(trigger_data));
    assert_int_equal(result.data_prefix_len, sizeof(result.data_prefix));
    assert_memory_equal(result.data_prefix, trigger_data, sizeof(result.data_prefix));

    assert_true(result.has_custom_data);
    assert_int_equal(result.custom_data_len, sizeof(custom_data));
    assert_int_equal(result.custom_data_prefix_len, sizeof(result.custom_data_prefix));
    assert_memory_equal(result.custom_data_prefix,
                        custom_data,
                        sizeof(result.custom_data_prefix));

    assert_int_equal(observer.calls, sizeof(trigger_data));
    assert_int_equal(observer.observed_len, sizeof(trigger_data));
    assert_memory_equal(observer.observed, trigger_data, sizeof(trigger_data));
}

static void test_decode_raw_message(void **state) {
    (void) state;

    const uint8_t owner[21] = {
        0x41, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
    };
    const uint8_t contract_address[21] = {
        0x41, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
        0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
        0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4,
    };
    const uint8_t trigger_data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    const uint8_t custom_data[] = {'T', 'R', 'X'};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    const test_buffer_t trigger = build_trigger_message(owner,
                                                        sizeof(owner),
                                                        contract_address,
                                                        sizeof(contract_address),
                                                        99U,
                                                        trigger_data,
                                                        sizeof(trigger_data),
                                                        0U,
                                                        0U);
    const test_buffer_t any = build_any_message(&trigger);
    const test_buffer_t contract =
        build_contract_message(&any,
                               protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                               2U);
    const test_buffer_t raw = build_raw_message(&contract, 321U, custom_data, sizeof(custom_data));

    tron_stream_decoder_init_raw(&decoder, raw.len);

    assert_true(tron_stream_decoder_feed(&decoder, raw.bytes, raw.len));
    assert_true(tron_stream_decoder_is_done(&decoder));
    assert_true(tron_stream_decoder_get_result(&decoder, &result));

    assert_true(result.has_fee_limit);
    assert_int_equal(result.fee_limit, 321);
    assert_true(result.has_contract_type);
    assert_int_equal(result.contract_type,
                     protocol_Transaction_Contract_ContractType_TriggerSmartContract);
    assert_true(result.has_permission_id);
    assert_int_equal(result.permission_id, 2);
    assert_true(result.has_call_value);
    assert_int_equal(result.call_value, 99);
    assert_true(result.has_owner_address);
    assert_memory_equal(result.owner_address, owner, sizeof(owner));
    assert_true(result.has_contract_address);
    assert_memory_equal(result.contract_address, contract_address, sizeof(contract_address));
    assert_true(result.has_data);
    assert_int_equal(result.data_len, sizeof(trigger_data));
    assert_int_equal(result.data_prefix_len, sizeof(trigger_data));
    assert_memory_equal(result.data_prefix, trigger_data, sizeof(trigger_data));
    assert_true(result.has_custom_data);
    assert_int_equal(result.custom_data_len, sizeof(custom_data));
    assert_int_equal(result.custom_data_prefix_len, sizeof(custom_data));
    assert_memory_equal(result.custom_data_prefix, custom_data, sizeof(custom_data));
}

static void test_observer_failure_marks_decoder_invalid(void **state) {
    (void) state;

    const uint8_t owner[21] = {0};
    const uint8_t contract_address[21] = {1};
    const uint8_t trigger_data[] = {0x01, 0x02, 0x03};
    const uint8_t custom_data[] = {0xAA};
    observer_ctx_t observer = {.fail_at_offset = 1U};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    const test_buffer_t trigger = build_trigger_message(owner,
                                                        sizeof(owner),
                                                        contract_address,
                                                        sizeof(contract_address),
                                                        7U,
                                                        trigger_data,
                                                        sizeof(trigger_data),
                                                        0U,
                                                        0U);
    const test_buffer_t any = build_any_message(&trigger);
    const test_buffer_t contract =
        build_contract_message(&any,
                               protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                               1U);
    const test_buffer_t raw = build_raw_message(&contract, 100U, custom_data, sizeof(custom_data));
    const test_buffer_t tx = build_transaction_message(&raw);

    tron_stream_decoder_init(&decoder, tx.len);
    tron_stream_decoder_set_trigger_data_observer(&decoder, observer_collect, &observer);

    assert_false(tron_stream_decoder_feed(&decoder, tx.bytes, tx.len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
    assert_false(tron_stream_decoder_feed(&decoder, tx.bytes, 1U));
    assert_int_equal(observer.calls, 2);
    assert_int_equal(observer.observed_len, 1);
    assert_memory_equal(observer.observed, trigger_data, 1);
}

static void test_rejects_extra_bytes_after_declared_total(void **state) {
    (void) state;

    const uint8_t owner[21] = {0x41};
    const uint8_t contract_address[21] = {0x42};
    const uint8_t trigger_data[] = {0x11, 0x22};
    const uint8_t custom_data[] = {0x55, 0x66};
    uint8_t encoded[1024];
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    const test_buffer_t trigger = build_trigger_message(owner,
                                                        sizeof(owner),
                                                        contract_address,
                                                        sizeof(contract_address),
                                                        1U,
                                                        trigger_data,
                                                        sizeof(trigger_data),
                                                        2U,
                                                        3U);
    const test_buffer_t any = build_any_message(&trigger);
    const test_buffer_t contract =
        build_contract_message(&any,
                               protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                               4U);
    const test_buffer_t raw = build_raw_message(&contract, 5U, custom_data, sizeof(custom_data));
    const test_buffer_t tx = build_transaction_message(&raw);

    memcpy(encoded, tx.bytes, tx.len);
    encoded[tx.len] = 0x00U;

    tron_stream_decoder_init(&decoder, tx.len);

    assert_false(tron_stream_decoder_feed(&decoder, encoded, tx.len + 1U));
    assert_true(tron_stream_decoder_is_done(&decoder));
    assert_true(tron_stream_decoder_get_result(&decoder, &result));
    assert_int_equal(result.fee_limit, 5);
}

static void test_skips_unknown_fields_and_fixed_width_wire_types(void **state) {
    (void) state;

    const uint8_t owner[21] = {
        0x41, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
    };
    const uint8_t contract_address[21] = {
        0x41, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6,
        0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
        0xFE, 0xFF, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4,
    };
    const uint8_t trigger_data[] = {0xBA, 0xAD, 0xF0, 0x0D};
    const uint8_t custom_data[] = {0xCA, 0xFE};
    const uint8_t top_level_signature[] = {0xAA, 0xBB};
    const uint8_t provider[] = {'d', 'e', 'm', 'o'};
    const uint8_t fixed32_value[4] = {0x44, 0x33, 0x22, 0x11};
    const uint8_t fixed64_value[8] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    test_buffer_t trigger = {0};
    test_buffer_t any = {0};
    test_buffer_t contract = {0};
    test_buffer_t raw = {0};
    test_buffer_t tx = {0};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_owner_address_tag,
                                   owner,
                                   sizeof(owner));
    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_contract_address_tag,
                                   contract_address,
                                   sizeof(contract_address));
    test_buffer_append_fixed64_field(&trigger, 9U, fixed64_value);
    test_buffer_append_varint_field(&trigger, protocol_TriggerSmartContract_call_value_tag, 42U);
    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_data_tag,
                                   trigger_data,
                                   sizeof(trigger_data));

    test_buffer_append_bytes_field(&any,
                                   google_protobuf_Any_type_url_tag,
                                   test_trigger_type_url,
                                   sizeof(test_trigger_type_url) - 1U);
    test_buffer_append_bytes_field(&any, google_protobuf_Any_value_tag, trigger.bytes, trigger.len);

    test_buffer_append_varint_field(&contract,
                                    protocol_Transaction_Contract_type_tag,
                                    protocol_Transaction_Contract_ContractType_TriggerSmartContract);
    test_buffer_append_bytes_field(&contract, 3U, provider, sizeof(provider));
    test_buffer_append_message_field(&contract, protocol_Transaction_Contract_parameter_tag, &any);
    test_buffer_append_varint_field(&contract, protocol_Transaction_Contract_Permission_id_tag, 12U);

    test_buffer_append_bytes_field(&raw,
                                   protocol_Transaction_raw_custom_data_tag,
                                   custom_data,
                                   sizeof(custom_data));
    test_buffer_append_fixed32_field(&raw, 12U, fixed32_value);
    test_buffer_append_message_field(&raw, protocol_Transaction_raw_contract_tag, &contract);
    test_buffer_append_varint_field(&raw, protocol_Transaction_raw_fee_limit_tag, 999U);

    test_buffer_append_bytes_field(&tx, protocol_Transaction_signature_tag, top_level_signature, 0U);
    test_buffer_append_message_field(&tx, protocol_Transaction_raw_data_tag, &raw);

    tron_stream_decoder_init(&decoder, tx.len);

    assert_true(tron_stream_decoder_feed(&decoder, tx.bytes, tx.len));
    assert_true(tron_stream_decoder_is_done(&decoder));
    assert_true(tron_stream_decoder_get_result(&decoder, &result));

    assert_true(result.has_contract_type);
    assert_int_equal(result.contract_type,
                     protocol_Transaction_Contract_ContractType_TriggerSmartContract);
    assert_true(result.has_permission_id);
    assert_int_equal(result.permission_id, 12);
    assert_true(result.has_fee_limit);
    assert_int_equal(result.fee_limit, 999);
    assert_true(result.has_call_value);
    assert_int_equal(result.call_value, 42);
    assert_true(result.has_owner_address);
    assert_memory_equal(result.owner_address, owner, sizeof(owner));
    assert_true(result.has_contract_address);
    assert_memory_equal(result.contract_address, contract_address, sizeof(contract_address));
    assert_true(result.has_data);
    assert_int_equal(result.data_len, sizeof(trigger_data));
    assert_int_equal(result.data_prefix_len, sizeof(trigger_data));
    assert_memory_equal(result.data_prefix, trigger_data, sizeof(trigger_data));
    assert_true(result.has_custom_data);
    assert_int_equal(result.custom_data_len, sizeof(custom_data));
    assert_int_equal(result.custom_data_prefix_len, sizeof(custom_data));
    assert_memory_equal(result.custom_data_prefix, custom_data, sizeof(custom_data));
}

static void test_handles_zero_length_fields_and_zero_length_decoder(void **state) {
    (void) state;

    const uint8_t owner[21] = {0x41};
    const uint8_t contract_address[21] = {0x42};
    const uint8_t empty_bytes[1] = {0};
    tron_stream_decoder_t decoder;
    tron_stream_decoder_t empty_decoder;
    tron_stream_decoder_t empty_raw_decoder;
    tron_decode_result_t result;

    const test_buffer_t trigger = build_trigger_message(owner,
                                                        sizeof(owner),
                                                        contract_address,
                                                        sizeof(contract_address),
                                                        0U,
                                                        empty_bytes,
                                                        0U,
                                                        0U,
                                                        0U);
    const test_buffer_t any = build_any_message(&trigger);
    const test_buffer_t contract =
        build_contract_message(&any,
                               protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                               0U);
    const test_buffer_t raw = build_raw_message(&contract, 0U, empty_bytes, 0U);
    const test_buffer_t tx = build_transaction_message(&raw);

    tron_stream_decoder_init(&decoder, tx.len);
    assert_true(tron_stream_decoder_feed(&decoder, tx.bytes, tx.len));
    assert_true(tron_stream_decoder_get_result(&decoder, &result));
    assert_true(result.has_custom_data);
    assert_int_equal(result.custom_data_len, 0);
    assert_int_equal(result.custom_data_prefix_len, 0);
    assert_true(result.has_data);
    assert_int_equal(result.data_len, 0);
    assert_int_equal(result.data_prefix_len, 0);

    tron_stream_decoder_init(&empty_decoder, 0U);
    assert_true(tron_stream_decoder_is_done(&empty_decoder));
    assert_true(tron_stream_decoder_get_result(&empty_decoder, &result));
    assert_false(result.has_data);
    assert_false(tron_stream_decoder_feed(&empty_decoder, empty_bytes, 0U));

    tron_stream_decoder_init_raw(&empty_raw_decoder, 0U);
    assert_true(tron_stream_decoder_is_done(&empty_raw_decoder));
    assert_true(tron_stream_decoder_get_result(&empty_raw_decoder, &result));
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
    tron_stream_decoder_t decoder;

    tron_stream_decoder_init(&decoder, sizeof(invalid_zero_tag));
    assert_false(tron_stream_decoder_feed(&decoder, invalid_zero_tag, sizeof(invalid_zero_tag)));
    assert_false(tron_stream_decoder_is_done(&decoder));

    tron_stream_decoder_init(&decoder, sizeof(invalid_large_tag));
    assert_false(tron_stream_decoder_feed(&decoder, invalid_large_tag, sizeof(invalid_large_tag)));
    assert_false(tron_stream_decoder_is_done(&decoder));

    tron_stream_decoder_init(&decoder, sizeof(invalid_wire));
    assert_false(tron_stream_decoder_feed(&decoder, invalid_wire, sizeof(invalid_wire)));
    assert_false(tron_stream_decoder_is_done(&decoder));

    tron_stream_decoder_init(&decoder, sizeof(invalid_length));
    assert_false(tron_stream_decoder_feed(&decoder, invalid_length, sizeof(invalid_length)));
    assert_false(tron_stream_decoder_is_done(&decoder));

    tron_stream_decoder_init_raw(&decoder, sizeof(invalid_value));
    assert_false(tron_stream_decoder_feed(&decoder, invalid_value, sizeof(invalid_value)));
    assert_false(tron_stream_decoder_is_done(&decoder));

    tron_stream_decoder_init(&decoder, sizeof(invalid_key));
    assert_false(tron_stream_decoder_feed(&decoder, invalid_key, sizeof(invalid_key)));
    assert_false(tron_stream_decoder_is_done(&decoder));
}

static void test_rejects_non_trigger_contract_type(void **state) {
    (void) state;

    const uint8_t owner[21] = {0x41};
    const uint8_t contract_address[21] = {0x42};
    const uint8_t trigger_data[] = {0x11, 0x22, 0x33, 0x44};
    const uint8_t custom_data[] = {0x55};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    const test_buffer_t trigger = build_trigger_message(owner,
                                                        sizeof(owner),
                                                        contract_address,
                                                        sizeof(contract_address),
                                                        1U,
                                                        trigger_data,
                                                        sizeof(trigger_data),
                                                        0U,
                                                        0U);
    const test_buffer_t any = build_any_message(&trigger);
    const test_buffer_t contract = build_contract_message_parameter_first(
        &any,
        protocol_Transaction_Contract_ContractType_TransferContract,
        1U);
    const test_buffer_t raw = build_raw_message(&contract, 5U, custom_data, sizeof(custom_data));

    tron_stream_decoder_init_raw(&decoder, raw.len);

    assert_false(tron_stream_decoder_feed(&decoder, raw.bytes, raw.len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
}

static void test_rejects_trigger_parameter_before_contract_type(void **state) {
    (void) state;

    const uint8_t owner[21] = {0x41};
    const uint8_t contract_address[21] = {0x42};
    const uint8_t trigger_data[] = {0x11, 0x22, 0x33, 0x44};
    const uint8_t custom_data[] = {0x55};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    const test_buffer_t trigger = build_trigger_message(owner,
                                                        sizeof(owner),
                                                        contract_address,
                                                        sizeof(contract_address),
                                                        1U,
                                                        trigger_data,
                                                        sizeof(trigger_data),
                                                        0U,
                                                        0U);
    const test_buffer_t any = build_any_message(&trigger);
    const test_buffer_t contract = build_contract_message_parameter_first(
        &any,
        protocol_Transaction_Contract_ContractType_TriggerSmartContract,
        1U);
    const test_buffer_t raw = build_raw_message(&contract, 5U, custom_data, sizeof(custom_data));

    tron_stream_decoder_init_raw(&decoder, raw.len);

    assert_false(tron_stream_decoder_feed(&decoder, raw.bytes, raw.len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
}

static void test_keeps_only_first_contract(void **state) {
    (void) state;

    const uint8_t owner1[21] = {0x41, 0x01};
    const uint8_t contract1[21] = {0x41, 0x11};
    const uint8_t data1[] = {0xAA, 0xBB, 0xCC, 0xDD};
    const uint8_t owner2[21] = {0x41, 0x02};
    const uint8_t contract2[21] = {0x41, 0x22};
    const uint8_t data2[] = {0x10, 0x20, 0x30, 0x40};
    const uint8_t custom_data[] = {0x99};
    test_buffer_t raw = {0};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    const test_buffer_t trigger1 = build_trigger_message(owner1,
                                                         sizeof(owner1),
                                                         contract1,
                                                         sizeof(contract1),
                                                         100U,
                                                         data1,
                                                         sizeof(data1),
                                                         1U,
                                                         2U);
    const test_buffer_t any1 = build_any_message(&trigger1);
    const test_buffer_t contract_msg1 =
        build_contract_message(&any1,
                               protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                               7U);
    const test_buffer_t trigger2 = build_trigger_message(owner2,
                                                         sizeof(owner2),
                                                         contract2,
                                                         sizeof(contract2),
                                                         200U,
                                                         data2,
                                                         sizeof(data2),
                                                         3U,
                                                         4U);
    const test_buffer_t any2 = build_any_message(&trigger2);
    const test_buffer_t contract_msg2 =
        build_contract_message(&any2,
                               protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                               8U);

    test_buffer_append_bytes_field(&raw,
                                   protocol_Transaction_raw_custom_data_tag,
                                   custom_data,
                                   sizeof(custom_data));
    test_buffer_append_message_field(&raw, protocol_Transaction_raw_contract_tag, &contract_msg1);
    test_buffer_append_message_field(&raw, protocol_Transaction_raw_contract_tag, &contract_msg2);
    test_buffer_append_varint_field(&raw, protocol_Transaction_raw_fee_limit_tag, 999U);

    tron_stream_decoder_init_raw(&decoder, raw.len);

    assert_true(tron_stream_decoder_feed(&decoder, raw.bytes, raw.len));
    assert_true(tron_stream_decoder_is_done(&decoder));
    assert_true(tron_stream_decoder_get_result(&decoder, &result));

    assert_int_equal(result.permission_id, 7);
    assert_int_equal(result.call_value, 100);
    assert_int_equal(result.call_token_value, 1);
    assert_int_equal(result.token_id, 2);
    assert_memory_equal(result.owner_address, owner1, sizeof(owner1));
    assert_memory_equal(result.contract_address, contract1, sizeof(contract1));
    assert_memory_equal(result.data_prefix, data1, sizeof(data1));
}

static void test_rejects_data_before_addresses(void **state) {
    (void) state;

    const uint8_t owner[21] = {0x41};
    const uint8_t contract_address[21] = {0x42};
    const uint8_t trigger_data[] = {0xAA, 0xBB, 0xCC, 0xDD};
    const uint8_t custom_data[] = {0x99};
    test_buffer_t trigger = {0};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_data_tag,
                                   trigger_data,
                                   sizeof(trigger_data));
    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_owner_address_tag,
                                   owner,
                                   sizeof(owner));
    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_contract_address_tag,
                                   contract_address,
                                   sizeof(contract_address));
    test_buffer_append_varint_field(&trigger, protocol_TriggerSmartContract_call_value_tag, 1U);

    const test_buffer_t any = build_any_message(&trigger);
    const test_buffer_t contract =
        build_contract_message(&any,
                               protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                               1U);
    const test_buffer_t raw = build_raw_message(&contract, 7U, custom_data, sizeof(custom_data));

    tron_stream_decoder_init_raw(&decoder, raw.len);

    assert_false(tron_stream_decoder_feed(&decoder, raw.bytes, raw.len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
}

static void test_rejects_duplicate_contract_parameter(void **state) {
    (void) state;

    const uint8_t owner1[21] = {0x41, 0x01};
    const uint8_t contract1[21] = {0x41, 0x11};
    const uint8_t data1[] = {0xAA, 0xBB, 0xCC, 0xDD};
    const uint8_t owner2[21] = {0x41, 0x02};
    const uint8_t contract2[21] = {0x41, 0x22};
    const uint8_t data2[] = {0x10, 0x20, 0x30, 0x40};
    const uint8_t custom_data[] = {0x99};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;
    test_buffer_t contract = {0};
    test_buffer_t raw = {0};

    const test_buffer_t trigger1 = build_trigger_message(owner1,
                                                         sizeof(owner1),
                                                         contract1,
                                                         sizeof(contract1),
                                                         100U,
                                                         data1,
                                                         sizeof(data1),
                                                         1U,
                                                         2U);
    const test_buffer_t trigger2 = build_trigger_message(owner2,
                                                         sizeof(owner2),
                                                         contract2,
                                                         sizeof(contract2),
                                                         200U,
                                                         data2,
                                                         sizeof(data2),
                                                         3U,
                                                         4U);
    const test_buffer_t any1 = build_any_message(&trigger1);
    const test_buffer_t any2 = build_any_message(&trigger2);

    test_buffer_append_varint_field(&contract,
                                    protocol_Transaction_Contract_type_tag,
                                    protocol_Transaction_Contract_ContractType_TriggerSmartContract);
    test_buffer_append_message_field(&contract, protocol_Transaction_Contract_parameter_tag, &any1);
    test_buffer_append_message_field(&contract, protocol_Transaction_Contract_parameter_tag, &any2);
    test_buffer_append_bytes_field(&raw,
                                   protocol_Transaction_raw_custom_data_tag,
                                   custom_data,
                                   sizeof(custom_data));
    test_buffer_append_message_field(&raw, protocol_Transaction_raw_contract_tag, &contract);
    test_buffer_append_varint_field(&raw, protocol_Transaction_raw_fee_limit_tag, 7U);

    tron_stream_decoder_init_raw(&decoder, raw.len);

    assert_false(tron_stream_decoder_feed(&decoder, raw.bytes, raw.len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
}

static void test_rejects_duplicate_any_value(void **state) {
    (void) state;

    const uint8_t owner1[21] = {0x41, 0x01};
    const uint8_t contract1[21] = {0x41, 0x11};
    const uint8_t data1[] = {0xAA, 0xBB, 0xCC, 0xDD};
    const uint8_t owner2[21] = {0x41, 0x02};
    const uint8_t contract2[21] = {0x41, 0x22};
    const uint8_t data2[] = {0x10, 0x20, 0x30, 0x40};
    const uint8_t custom_data[] = {0x99};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;
    test_buffer_t any = {0};
    test_buffer_t contract = {0};
    test_buffer_t raw = {0};

    const test_buffer_t trigger1 = build_trigger_message(owner1,
                                                         sizeof(owner1),
                                                         contract1,
                                                         sizeof(contract1),
                                                         100U,
                                                         data1,
                                                         sizeof(data1),
                                                         1U,
                                                         2U);
    const test_buffer_t trigger2 = build_trigger_message(owner2,
                                                         sizeof(owner2),
                                                         contract2,
                                                         sizeof(contract2),
                                                         200U,
                                                         data2,
                                                         sizeof(data2),
                                                         3U,
                                                         4U);
    test_buffer_append_bytes_field(&any,
                                   google_protobuf_Any_type_url_tag,
                                   test_trigger_type_url,
                                   sizeof(test_trigger_type_url) - 1U);
    test_buffer_append_bytes_field(&any, google_protobuf_Any_value_tag, trigger1.bytes, trigger1.len);
    test_buffer_append_bytes_field(&any, google_protobuf_Any_value_tag, trigger2.bytes, trigger2.len);
    contract = build_contract_message(&any,
                                      protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                                      1U);
    raw = build_raw_message(&contract, 7U, custom_data, sizeof(custom_data));

    tron_stream_decoder_init_raw(&decoder, raw.len);

    assert_false(tron_stream_decoder_feed(&decoder, raw.bytes, raw.len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
}

static void test_rejects_missing_any_type_url(void **state) {
    (void) state;

    const uint8_t owner[21] = {0x41};
    const uint8_t contract_address[21] = {0x42};
    const uint8_t trigger_data[] = {0xAA, 0xBB, 0xCC, 0xDD};
    const uint8_t custom_data[] = {0x99};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;
    test_buffer_t any = {0};
    test_buffer_t contract = {0};
    test_buffer_t raw = {0};

    const test_buffer_t trigger = build_trigger_message(owner,
                                                        sizeof(owner),
                                                        contract_address,
                                                        sizeof(contract_address),
                                                        1U,
                                                        trigger_data,
                                                        sizeof(trigger_data),
                                                        0U,
                                                        0U);
    test_buffer_append_bytes_field(&any, google_protobuf_Any_value_tag, trigger.bytes, trigger.len);
    contract = build_contract_message(&any,
                                      protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                                      1U);
    raw = build_raw_message(&contract, 7U, custom_data, sizeof(custom_data));

    tron_stream_decoder_init_raw(&decoder, raw.len);

    assert_false(tron_stream_decoder_feed(&decoder, raw.bytes, raw.len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
}

static void test_rejects_invalid_any_type_url(void **state) {
    (void) state;

    const uint8_t owner[21] = {0x41};
    const uint8_t contract_address[21] = {0x42};
    const uint8_t trigger_data[] = {0xAA, 0xBB, 0xCC, 0xDD};
    const uint8_t custom_data[] = {0x99};
    const uint8_t invalid_type_url[] = "type.googleapis.com/protocol.TransferContract";
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;
    test_buffer_t any = {0};
    test_buffer_t contract = {0};
    test_buffer_t raw = {0};

    const test_buffer_t trigger = build_trigger_message(owner,
                                                        sizeof(owner),
                                                        contract_address,
                                                        sizeof(contract_address),
                                                        1U,
                                                        trigger_data,
                                                        sizeof(trigger_data),
                                                        0U,
                                                        0U);
    test_buffer_append_bytes_field(&any,
                                   google_protobuf_Any_type_url_tag,
                                   invalid_type_url,
                                   sizeof(invalid_type_url) - 1U);
    test_buffer_append_bytes_field(&any, google_protobuf_Any_value_tag, trigger.bytes, trigger.len);
    contract = build_contract_message(&any,
                                      protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                                      1U);
    raw = build_raw_message(&contract, 7U, custom_data, sizeof(custom_data));

    tron_stream_decoder_init_raw(&decoder, raw.len);

    assert_false(tron_stream_decoder_feed(&decoder, raw.bytes, raw.len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
}

static void test_rejects_duplicate_trigger_singleton_field(void **state) {
    (void) state;

    const uint8_t owner1[21] = {0x41, 0x01};
    const uint8_t owner2[21] = {0x41, 0x02};
    const uint8_t contract_address[21] = {0x42};
    const uint8_t trigger_data[] = {0xAA, 0xBB, 0xCC, 0xDD};
    const uint8_t custom_data[] = {0x99};
    test_buffer_t trigger = {0};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_owner_address_tag,
                                   owner1,
                                   sizeof(owner1));
    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_contract_address_tag,
                                   contract_address,
                                   sizeof(contract_address));
    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_data_tag,
                                   trigger_data,
                                   sizeof(trigger_data));
    test_buffer_append_bytes_field(&trigger,
                                   protocol_TriggerSmartContract_owner_address_tag,
                                   owner2,
                                   sizeof(owner2));
    test_buffer_append_varint_field(&trigger, protocol_TriggerSmartContract_call_value_tag, 1U);

    const test_buffer_t any = build_any_message(&trigger);
    const test_buffer_t contract =
        build_contract_message(&any,
                               protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                               1U);
    const test_buffer_t raw = build_raw_message(&contract, 7U, custom_data, sizeof(custom_data));

    tron_stream_decoder_init_raw(&decoder, raw.len);

    assert_false(tron_stream_decoder_feed(&decoder, raw.bytes, raw.len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
}

static void test_rejects_length_exceeding_remaining_bytes(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;
    tron_decode_result_t result;
    test_buffer_t raw = {0};

    test_buffer_append_key(&raw, protocol_Transaction_raw_custom_data_tag, PB_WT_STRING);
    test_buffer_append_varint(&raw, 3U);
    test_buffer_append_byte(&raw, 0xAAU);

    tron_stream_decoder_init_raw(&decoder, raw.len);

    assert_false(tron_stream_decoder_feed(&decoder, raw.bytes, raw.len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
}

static void test_truncated_terminal_varint_is_not_marked_done(void **state) {
    (void) state;

    const uint8_t raw[] = {
        0x90U, 0x01U, /* fee_limit key */
        0x80U,        /* truncated varint payload */
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

    const uint8_t owner[21] = {0x41};
    const uint8_t contract_address[21] = {0x42};
    const uint8_t trigger_data[] = {0x11, 0x22, 0x33, 0x44};
    const uint8_t custom_data[] = {0x55};
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;

    const test_buffer_t trigger_negative = build_trigger_message(owner,
                                                                 sizeof(owner),
                                                                 contract_address,
                                                                 sizeof(contract_address),
                                                                 UINT64_MAX,
                                                                 trigger_data,
                                                                 sizeof(trigger_data),
                                                                 0U,
                                                                 0U);
    const test_buffer_t any_negative = build_any_message(&trigger_negative);
    const test_buffer_t contract_negative =
        build_contract_message(&any_negative,
                               protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                               1U);
    const test_buffer_t raw_negative =
        build_raw_message(&contract_negative, 5U, custom_data, sizeof(custom_data));

    tron_stream_decoder_init_raw(&decoder, raw_negative.len);
    assert_false(tron_stream_decoder_feed(&decoder, raw_negative.bytes, raw_negative.len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));

    const test_buffer_t trigger_permission = build_trigger_message(owner,
                                                                   sizeof(owner),
                                                                   contract_address,
                                                                   sizeof(contract_address),
                                                                   1U,
                                                                   trigger_data,
                                                                   sizeof(trigger_data),
                                                                   0U,
                                                                   0U);
    const test_buffer_t any_permission = build_any_message(&trigger_permission);
    const test_buffer_t contract_permission =
        build_contract_message(&any_permission,
                               protocol_Transaction_Contract_ContractType_TriggerSmartContract,
                               300U);
    const test_buffer_t raw_permission =
        build_raw_message(&contract_permission, 5U, custom_data, sizeof(custom_data));

    tron_stream_decoder_init_raw(&decoder, raw_permission.len);
    assert_false(tron_stream_decoder_feed(&decoder, raw_permission.bytes, raw_permission.len));
    assert_false(tron_stream_decoder_is_done(&decoder));
    assert_false(tron_stream_decoder_get_result(&decoder, &result));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_decode_transaction_in_chunks),
        cmocka_unit_test(test_decode_raw_message),
        cmocka_unit_test(test_observer_failure_marks_decoder_invalid),
        cmocka_unit_test(test_rejects_extra_bytes_after_declared_total),
        cmocka_unit_test(test_skips_unknown_fields_and_fixed_width_wire_types),
        cmocka_unit_test(test_handles_zero_length_fields_and_zero_length_decoder),
        cmocka_unit_test(test_api_argument_guards),
        cmocka_unit_test(test_rejects_invalid_wire_type_and_overlong_varints),
        cmocka_unit_test(test_rejects_non_trigger_contract_type),
        cmocka_unit_test(test_rejects_trigger_parameter_before_contract_type),
        cmocka_unit_test(test_keeps_only_first_contract),
        cmocka_unit_test(test_rejects_data_before_addresses),
        cmocka_unit_test(test_rejects_duplicate_contract_parameter),
        cmocka_unit_test(test_rejects_duplicate_any_value),
        cmocka_unit_test(test_rejects_missing_any_type_url),
        cmocka_unit_test(test_rejects_invalid_any_type_url),
        cmocka_unit_test(test_rejects_duplicate_trigger_singleton_field),
        cmocka_unit_test(test_rejects_length_exceeding_remaining_bytes),
        cmocka_unit_test(test_truncated_terminal_varint_is_not_marked_done),
        cmocka_unit_test(test_rejects_out_of_range_numeric_fields),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
