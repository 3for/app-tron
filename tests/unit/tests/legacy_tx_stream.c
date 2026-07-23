#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "legacy_tx_stream.h"
#include "google/protobuf/any.pb.h"
#include "pb_decode.h"

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} test_buffer_t;

static void buffer_free(test_buffer_t *buffer) {
    free(buffer->data);
    memset(buffer, 0, sizeof(*buffer));
}

static void buffer_reserve(test_buffer_t *buffer, size_t extra) {
    assert_true(extra <= SIZE_MAX - buffer->len);
    size_t needed = buffer->len + extra;
    if (needed <= buffer->cap) {
        return;
    }
    size_t new_cap = buffer->cap == 0U ? 128U : buffer->cap;
    while (new_cap < needed) {
        assert_true(new_cap <= SIZE_MAX / 2U);
        new_cap *= 2U;
    }
    uint8_t *next = realloc(buffer->data, new_cap);
    assert_non_null(next);
    buffer->data = next;
    buffer->cap = new_cap;
}

static void buffer_append(test_buffer_t *buffer, const void *data, size_t len) {
    buffer_reserve(buffer, len);
    if (len != 0U) {
        memcpy(buffer->data + buffer->len, data, len);
    }
    buffer->len += len;
}

static void buffer_append_fill(test_buffer_t *buffer, uint8_t value, size_t len) {
    buffer_reserve(buffer, len);
    memset(buffer->data + buffer->len, value, len);
    buffer->len += len;
}

static void buffer_append_varint(test_buffer_t *buffer, uint64_t value) {
    do {
        uint8_t byte = (uint8_t) (value & 0x7FU);
        value >>= 7U;
        if (value != 0U) {
            byte |= 0x80U;
        }
        buffer_append(buffer, &byte, 1U);
    } while (value != 0U);
}

static void buffer_append_key(test_buffer_t *buffer, uint32_t tag, uint8_t wire) {
    buffer_append_varint(buffer, ((uint64_t) tag << 3U) | wire);
}

static void buffer_append_varint_field(test_buffer_t *buffer, uint32_t tag, uint64_t value) {
    buffer_append_key(buffer, tag, PB_WT_VARINT);
    buffer_append_varint(buffer, value);
}

static void buffer_append_bytes_field(test_buffer_t *buffer,
                                      uint32_t tag,
                                      const uint8_t *data,
                                      size_t len) {
    buffer_append_key(buffer, tag, PB_WT_STRING);
    buffer_append_varint(buffer, len);
    buffer_append(buffer, data, len);
}

static test_buffer_t build_contract(size_t parameter_len, bool reordered, const char *type_url) {
    test_buffer_t any = {0};
    test_buffer_t contract = {0};
    uint8_t *parameter = malloc(parameter_len == 0U ? 1U : parameter_len);
    assert_non_null(parameter);
    for (size_t i = 0; i < parameter_len; i++) {
        parameter[i] = (uint8_t) i;
    }

    if (reordered) {
        buffer_append_bytes_field(&any, google_protobuf_Any_value_tag, parameter, parameter_len);
        buffer_append_bytes_field(&any,
                                  google_protobuf_Any_type_url_tag,
                                  (const uint8_t *) type_url,
                                  strlen(type_url));
        buffer_append_bytes_field(&contract,
                                  protocol_Transaction_Contract_parameter_tag,
                                  any.data,
                                  any.len);
        buffer_append_varint_field(&contract, protocol_Transaction_Contract_Permission_id_tag, 2U);
        buffer_append_varint_field(&contract,
                                   protocol_Transaction_Contract_type_tag,
                                   protocol_Transaction_Contract_ContractType_TransferContract);
    } else {
        buffer_append_varint_field(&contract,
                                   protocol_Transaction_Contract_type_tag,
                                   protocol_Transaction_Contract_ContractType_TransferContract);
        buffer_append_bytes_field(&any,
                                  google_protobuf_Any_type_url_tag,
                                  (const uint8_t *) type_url,
                                  strlen(type_url));
        buffer_append_bytes_field(&any, google_protobuf_Any_value_tag, parameter, parameter_len);
        buffer_append_bytes_field(&contract,
                                  protocol_Transaction_Contract_parameter_tag,
                                  any.data,
                                  any.len);
        buffer_append_varint_field(&contract, protocol_Transaction_Contract_Permission_id_tag, 2U);
    }

    free(parameter);
    buffer_free(&any);
    return contract;
}

static test_buffer_t build_raw(size_t memo_len,
                               size_t parameter_len,
                               bool reordered,
                               const char *type_url,
                               unsigned contract_count) {
    test_buffer_t raw = {0};
    test_buffer_t contract = build_contract(parameter_len, reordered, type_url);

    if (memo_len != 0U) {
        buffer_append_key(&raw, protocol_Transaction_raw_custom_data_tag, PB_WT_STRING);
        buffer_append_varint(&raw, memo_len);
        buffer_append_fill(&raw, 0xA5U, memo_len);
    }
    for (unsigned i = 0; i < contract_count; i++) {
        buffer_append_bytes_field(&raw,
                                  protocol_Transaction_raw_contract_tag,
                                  contract.data,
                                  contract.len);
    }
    buffer_append_varint_field(&raw, protocol_Transaction_raw_fee_limit_tag, 123456U);
    buffer_free(&contract);
    return raw;
}

static bool feed_in_chunks(legacy_tx_stream_t *stream,
                           const test_buffer_t *raw,
                           size_t chunk_size) {
    size_t offset = 0;
    while (offset < raw->len) {
        size_t take = raw->len - offset;
        if (take > chunk_size) {
            take = chunk_size;
        }
        if (!legacy_tx_stream_feed(stream, raw->data + offset, take)) {
            return false;
        }
        offset += take;
    }
    return true;
}

typedef struct {
    size_t begin_count;
    size_t chunk_count;
    size_t end_count;
    size_t declared_len;
    size_t observed_len;
    size_t largest_chunk;
} parameter_observer_capture_t;

static void capture_parameter_begin(void *ctx, size_t parameter_len) {
    parameter_observer_capture_t *capture = ctx;
    capture->begin_count++;
    capture->declared_len = parameter_len;
}

static void capture_parameter_chunk(void *ctx,
                                    const uint8_t *data,
                                    size_t data_len) {
    parameter_observer_capture_t *capture = ctx;
    assert_non_null(data);
    capture->chunk_count++;
    capture->observed_len += data_len;
    if (data_len > capture->largest_chunk) {
        capture->largest_chunk = data_len;
    }
}

static void capture_parameter_end(void *ctx) {
    parameter_observer_capture_t *capture = ctx;
    capture->end_count++;
}

typedef struct {
    const uint8_t *parameter;
    size_t parameter_len;
    uint64_t custom_data_len;
} whole_decode_capture_t;

static bool capture_parameter(pb_istream_t *stream, const pb_field_t *field, void **arg) {
    (void) field;
    whole_decode_capture_t *capture = *arg;
    capture->parameter = stream->state;
    capture->parameter_len = stream->bytes_left;
    return true;
}

static bool capture_custom_data_size(pb_istream_t *stream, const pb_field_t *field, void **arg) {
    (void) field;
    whole_decode_capture_t *capture = *arg;
    capture->custom_data_len = stream->bytes_left;
    return true;
}

static void test_matches_whole_nanopb_decode(void **state) {
    (void) state;
    static const char type_url[] = "type.googleapis.com/protocol.TransferContract";
    test_buffer_t raw = build_raw(320U, 73U, false, type_url, 1U);
    legacy_tx_stream_t *stream = calloc(1U, sizeof(*stream));
    legacy_tx_stream_result_t streamed;
    protocol_Transaction_raw decoded = protocol_Transaction_raw_init_zero;
    whole_decode_capture_t whole = {0};
    pb_istream_t input = pb_istream_from_buffer(raw.data, raw.len);
    assert_non_null(stream);

    decoded.contract[0].parameter.value.funcs.decode = capture_parameter;
    decoded.contract[0].parameter.value.arg = &whole;
    decoded.custom_data.funcs.decode = capture_custom_data_size;
    decoded.custom_data.arg = &whole;
    assert_true(pb_decode(&input, protocol_Transaction_raw_fields, &decoded));

    legacy_tx_stream_init(stream, NULL);
    assert_true(feed_in_chunks(stream, &raw, 13U));
    assert_true(legacy_tx_stream_finish(stream, &streamed));

    assert_int_equal(decoded.contract_count, 1U);
    assert_int_equal(streamed.contract_type, decoded.contract[0].type);
    assert_int_equal(streamed.permission_id, decoded.contract[0].Permission_id);
    assert_int_equal(streamed.fee_limit, decoded.fee_limit);
    assert_int_equal(streamed.custom_data_len, whole.custom_data_len);
    assert_int_equal(streamed.parameter_len, whole.parameter_len);
    assert_memory_equal(streamed.parameter, whole.parameter, whole.parameter_len);

    free(stream);
    buffer_free(&raw);
}

static void test_large_memo_and_reordered_fields(void **state) {
    (void) state;
    static const char type_url[] = "type.googleapis.com/protocol.TransferContract";
    test_buffer_t raw = build_raw(64U * 1024U, 73U, true, type_url, 1U);
    legacy_tx_stream_t *stream = calloc(1U, sizeof(*stream));
    legacy_tx_stream_result_t result;
    assert_non_null(stream);

    legacy_tx_stream_init(stream, NULL);
    assert_true(feed_in_chunks(stream, &raw, 1U));
    assert_true(legacy_tx_stream_finish(stream, &result));
    assert_int_equal(result.contract_type,
                     protocol_Transaction_Contract_ContractType_TransferContract);
    assert_int_equal(result.permission_id, 2);
    assert_int_equal(result.fee_limit, 123456);
    assert_int_equal(result.custom_data_len, 64U * 1024U);
    assert_int_equal(result.parameter_len, 73U);
    for (size_t i = 0; i < result.parameter_len; i++) {
        assert_int_equal(result.parameter[i], (uint8_t) i);
    }

    free(stream);
    buffer_free(&raw);
}

static void test_parameter_limit(void **state) {
    (void) state;
    static const char type_url[] = "type.googleapis.com/protocol.TransferContract";
    test_buffer_t accepted = build_raw(0U, LEGACY_TX_MAX_PARAMETER_SIZE, false, type_url, 1U);
    test_buffer_t rejected = build_raw(0U, LEGACY_TX_MAX_PARAMETER_SIZE + 1U, false, type_url, 1U);
    legacy_tx_stream_t *stream = calloc(1U, sizeof(*stream));
    legacy_tx_stream_result_t result;
    assert_non_null(stream);

    legacy_tx_stream_init(stream, NULL);
    assert_true(feed_in_chunks(stream, &accepted, 251U));
    assert_true(legacy_tx_stream_finish(stream, &result));
    assert_int_equal(result.parameter_len, LEGACY_TX_MAX_PARAMETER_SIZE);
    assert_false(result.parameter_overflow);

    legacy_tx_stream_init(stream, NULL);
    assert_true(feed_in_chunks(stream, &rejected, 251U));
    assert_true(legacy_tx_stream_finish(stream, &result));
    assert_int_equal(result.parameter_len, LEGACY_TX_MAX_PARAMETER_SIZE + 1U);
    assert_true(result.parameter_overflow);
    assert_null(result.parameter);

    free(stream);
    buffer_free(&accepted);
    buffer_free(&rejected);
}

static void test_rejects_incomplete_and_second_contract(void **state) {
    (void) state;
    static const char type_url[] = "type.googleapis.com/protocol.TransferContract";
    test_buffer_t raw = build_raw(32U, 8U, false, type_url, 1U);
    test_buffer_t two_contracts = build_raw(0U, 8U, false, type_url, 2U);
    legacy_tx_stream_t *stream = calloc(1U, sizeof(*stream));
    legacy_tx_stream_result_t result;
    assert_non_null(stream);

    legacy_tx_stream_init(stream, NULL);
    assert_true(legacy_tx_stream_feed(stream, raw.data, raw.len - 1U));
    assert_false(legacy_tx_stream_finish(stream, &result));

    legacy_tx_stream_init(stream, NULL);
    assert_false(feed_in_chunks(stream, &two_contracts, 17U));

    free(stream);
    buffer_free(&raw);
    buffer_free(&two_contracts);
}

static void test_rejects_mismatched_type_url(void **state) {
    (void) state;
    test_buffer_t raw =
        build_raw(0U, 8U, false, "type.googleapis.com/protocol.VoteWitnessContract", 1U);
    legacy_tx_stream_t *stream = calloc(1U, sizeof(*stream));
    legacy_tx_stream_result_t result;
    assert_non_null(stream);

    legacy_tx_stream_init(stream, NULL);
    assert_true(feed_in_chunks(stream, &raw, 7U));
    assert_false(legacy_tx_stream_finish(stream, &result));

    free(stream);
    buffer_free(&raw);
}

static void test_raw_size_limit(void **state) {
    (void) state;
    static const char type_url[] = "type.googleapis.com/protocol.TransferContract";
    test_buffer_t accepted = build_raw(LEGACY_TX_MAX_RAW_SIZE - 256U,
                                       8U,
                                       false,
                                       type_url,
                                       1U);
    test_buffer_t rejected = build_raw(LEGACY_TX_MAX_RAW_SIZE,
                                       8U,
                                       false,
                                       type_url,
                                       1U);
    legacy_tx_stream_t *stream = calloc(1U, sizeof(*stream));
    legacy_tx_stream_result_t result;
    assert_non_null(stream);

    assert_true(accepted.len <= LEGACY_TX_MAX_RAW_SIZE);
    legacy_tx_stream_init(stream, NULL);
    assert_true(feed_in_chunks(stream, &accepted, 251U));
    assert_true(legacy_tx_stream_finish(stream, &result));

    assert_true(rejected.len > LEGACY_TX_MAX_RAW_SIZE);
    legacy_tx_stream_init(stream, NULL);
    assert_false(feed_in_chunks(stream, &rejected, 251U));

    free(stream);
    buffer_free(&accepted);
    buffer_free(&rejected);
}

static void test_parameter_observer_lifecycle_and_chunks(void **state) {
    (void) state;
    static const char type_url[] = "type.googleapis.com/protocol.TransferContract";
    test_buffer_t raw = build_raw(0U, 5000U, false, type_url, 1U);
    legacy_tx_stream_t *stream = calloc(1U, sizeof(*stream));
    legacy_tx_stream_result_t result;
    parameter_observer_capture_t capture = {0};
    const legacy_parameter_observer_t observer = {
        .on_begin = capture_parameter_begin,
        .on_chunk = capture_parameter_chunk,
        .on_end = capture_parameter_end,
        .ctx = &capture,
    };
    assert_non_null(stream);

    legacy_tx_stream_init(stream, &observer);
    assert_true(feed_in_chunks(stream, &raw, 251U));
    assert_true(legacy_tx_stream_finish(stream, &result));
    assert_true(result.parameter_overflow);
    assert_int_equal(capture.begin_count, 1U);
    assert_int_equal(capture.end_count, 1U);
    assert_int_equal(capture.declared_len, 5000U);
    assert_int_equal(capture.observed_len, 5000U);
    assert_true(capture.chunk_count < capture.observed_len);
    assert_true(capture.largest_chunk > 1U);

    free(stream);
    buffer_free(&raw);
}

static void test_zero_length_parameter_observer(void **state) {
    (void) state;
    static const char type_url[] = "type.googleapis.com/protocol.TransferContract";
    test_buffer_t raw = build_raw(0U, 0U, false, type_url, 1U);
    legacy_tx_stream_t *stream = calloc(1U, sizeof(*stream));
    legacy_tx_stream_result_t result;
    parameter_observer_capture_t capture = {0};
    const legacy_parameter_observer_t observer = {
        .on_begin = capture_parameter_begin,
        .on_chunk = capture_parameter_chunk,
        .on_end = capture_parameter_end,
        .ctx = &capture,
    };
    assert_non_null(stream);

    legacy_tx_stream_init(stream, &observer);
    assert_true(feed_in_chunks(stream, &raw, 17U));
    assert_true(legacy_tx_stream_finish(stream, &result));
    assert_false(result.parameter_overflow);
    assert_int_equal(result.parameter_len, 0U);
    assert_int_equal(capture.begin_count, 1U);
    assert_int_equal(capture.chunk_count, 0U);
    assert_int_equal(capture.end_count, 1U);

    free(stream);
    buffer_free(&raw);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_matches_whole_nanopb_decode),
        cmocka_unit_test(test_large_memo_and_reordered_fields),
        cmocka_unit_test(test_parameter_limit),
        cmocka_unit_test(test_rejects_incomplete_and_second_contract),
        cmocka_unit_test(test_rejects_mismatched_type_url),
        cmocka_unit_test(test_raw_size_limit),
        cmocka_unit_test(test_parameter_observer_lifecycle_and_chunks),
        cmocka_unit_test(test_zero_length_parameter_observer),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
