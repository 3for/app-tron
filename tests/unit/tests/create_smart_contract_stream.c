#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "create_smart_contract_stream.h"

#define ABI_TAG 3U

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
    const size_t needed = buffer->len + extra;
    if (needed <= buffer->cap) {
        return;
    }
    size_t cap = buffer->cap == 0U ? 128U : buffer->cap;
    while (cap < needed) {
        assert_true(cap <= SIZE_MAX / 2U);
        cap *= 2U;
    }
    uint8_t *next = realloc(buffer->data, cap);
    assert_non_null(next);
    buffer->data = next;
    buffer->cap = cap;
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

static void buffer_append_varint_field(test_buffer_t *buffer,
                                       uint32_t tag,
                                       uint64_t value) {
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

static void buffer_append_fill_field(test_buffer_t *buffer,
                                     uint32_t tag,
                                     uint8_t value,
                                     size_t len) {
    buffer_append_key(buffer, tag, PB_WT_STRING);
    buffer_append_varint(buffer, len);
    buffer_append_fill(buffer, value, len);
}

static test_buffer_t build_create_with_name(size_t bytecode_len,
                                            bool include_bytecode,
                                            size_t abi_len,
                                            bool include_new_contract_twice,
                                            const uint8_t *name,
                                            size_t name_len) {
    test_buffer_t inner = {0};
    test_buffer_t outer = {0};
    uint8_t owner[21];
    memset(owner, 0x22, sizeof(owner));
    owner[0] = 0x41;

    buffer_append_bytes_field(&inner,
                              protocol_SmartContract_origin_address_tag,
                              owner,
                              sizeof(owner));
    if (abi_len != 0U) {
        buffer_append_fill_field(&inner, ABI_TAG, 0xA5U, abi_len);
    }
    if (include_bytecode) {
        buffer_append_fill_field(&inner,
                                 protocol_SmartContract_bytecode_tag,
                                 0x5AU,
                                 bytecode_len);
    }
    buffer_append_varint_field(&inner,
                               protocol_SmartContract_call_value_tag,
                               123U);
    buffer_append_varint_field(
        &inner,
        protocol_SmartContract_consume_user_resource_percent_tag,
        30U);
    buffer_append_bytes_field(&inner,
                              protocol_SmartContract_name_tag,
                              name,
                              name_len);
    buffer_append_varint_field(
        &inner,
        protocol_SmartContract_origin_energy_limit_tag,
        10000000U);

    buffer_append_bytes_field(&outer,
                              protocol_CreateSmartContract_owner_address_tag,
                              owner,
                              sizeof(owner));
    buffer_append_bytes_field(&outer,
                              protocol_CreateSmartContract_new_contract_tag,
                              inner.data,
                              inner.len);
    if (include_new_contract_twice) {
        buffer_append_bytes_field(&outer,
                                  protocol_CreateSmartContract_new_contract_tag,
                                  inner.data,
                                  inner.len);
    }
    buffer_append_varint_field(
        &outer,
        protocol_CreateSmartContract_call_token_value_tag,
        456U);
    buffer_append_varint_field(&outer,
                               protocol_CreateSmartContract_token_id_tag,
                               1000001U);
    buffer_free(&inner);
    return outer;
}

static test_buffer_t build_create(size_t bytecode_len,
                                  bool include_bytecode,
                                  size_t abi_len,
                                  bool include_new_contract_twice) {
    static const uint8_t name[] = "LedgerContract";

    return build_create_with_name(bytecode_len,
                                  include_bytecode,
                                  abi_len,
                                  include_new_contract_twice,
                                  name,
                                  sizeof(name) - 1U);
}

static bool feed_in_chunks(create_smart_contract_stream_t *stream,
                           const test_buffer_t *parameter,
                           size_t chunk_size) {
    size_t offset = 0U;
    while (offset < parameter->len) {
        size_t take = parameter->len - offset;
        if (take > chunk_size) {
            take = chunk_size;
        }
        if (!create_smart_contract_stream_feed(stream,
                                               parameter->data + offset,
                                               take)) {
            return false;
        }
        offset += take;
    }
    return true;
}

static void test_small_create_and_hash(void **state) {
    (void) state;
    test_buffer_t parameter = build_create(257U, true, 0U, false);
    create_smart_contract_stream_t stream;
    create_smart_contract_stream_result_t result;
    uint8_t expected_hash[32];
    uint8_t bytecode[257];
    memset(bytecode, 0x5A, sizeof(bytecode));

    create_smart_contract_stream_init(&stream, parameter.len);
    assert_true(feed_in_chunks(&stream, &parameter, 11U));
    assert_true(create_smart_contract_stream_finish(&stream, &result));

    assert_true(result.contract.has_new_contract);
    assert_int_equal(result.contract.owner_address[0], 0x41);
    assert_memory_equal(result.contract.owner_address,
                        result.contract.new_contract.origin_address,
                        sizeof(result.contract.owner_address));
    assert_string_equal(result.contract.new_contract.name, "LedgerContract");
    assert_int_equal(result.bytecode_size, sizeof(bytecode));
    assert_int_equal(cx_hash_sha256(bytecode,
                                    sizeof(bytecode),
                                    expected_hash,
                                    sizeof(expected_hash)),
                     sizeof(expected_hash));
    assert_memory_equal(result.bytecode_hash,
                        expected_hash,
                        sizeof(expected_hash));

    buffer_free(&parameter);
}

static void test_large_bytecode_and_abi(void **state) {
    (void) state;
    test_buffer_t parameter = build_create(24U * 1024U, true, 5000U, false);
    create_smart_contract_stream_t stream;
    create_smart_contract_stream_result_t result;

    create_smart_contract_stream_init(&stream, parameter.len);
    assert_true(feed_in_chunks(&stream, &parameter, 251U));
    assert_true(create_smart_contract_stream_finish(&stream, &result));
    assert_int_equal(result.bytecode_size, 24U * 1024U);
    assert_int_equal(result.abi_size, 5000U);
    assert_true(result.contract.has_new_contract);

    buffer_free(&parameter);
}

static void test_absent_and_empty_bytecode_match(void **state) {
    (void) state;
    test_buffer_t absent = build_create(0U, false, 0U, false);
    test_buffer_t empty = build_create(0U, true, 0U, false);
    create_smart_contract_stream_t stream;
    create_smart_contract_stream_result_t absent_result;
    create_smart_contract_stream_result_t empty_result;
    uint8_t expected_hash[32];

    create_smart_contract_stream_init(&stream, absent.len);
    assert_true(feed_in_chunks(&stream, &absent, 7U));
    assert_true(create_smart_contract_stream_finish(&stream, &absent_result));

    create_smart_contract_stream_init(&stream, empty.len);
    assert_true(feed_in_chunks(&stream, &empty, 7U));
    assert_true(create_smart_contract_stream_finish(&stream, &empty_result));

    assert_int_equal(cx_hash_sha256(NULL,
                                    0U,
                                    expected_hash,
                                    sizeof(expected_hash)),
                     sizeof(expected_hash));
    assert_memory_equal(absent_result.bytecode_hash,
                        expected_hash,
                        sizeof(expected_hash));
    assert_memory_equal(empty_result.bytecode_hash,
                        expected_hash,
                        sizeof(expected_hash));

    buffer_free(&absent);
    buffer_free(&empty);
}

static void test_rejects_duplicate_new_contract(void **state) {
    (void) state;
    test_buffer_t parameter = build_create(10U, true, 0U, true);
    create_smart_contract_stream_t stream;

    create_smart_contract_stream_init(&stream, parameter.len);
    assert_false(feed_in_chunks(&stream, &parameter, 19U));
    buffer_free(&parameter);
}

static void test_rejects_truncation(void **state) {
    (void) state;
    test_buffer_t parameter = build_create(5000U, true, 0U, false);
    create_smart_contract_stream_t stream;
    create_smart_contract_stream_result_t result;

    create_smart_contract_stream_init(&stream, parameter.len);
    assert_true(create_smart_contract_stream_feed(&stream,
                                                  parameter.data,
                                                  parameter.len - 1U));
    assert_false(create_smart_contract_stream_finish(&stream, &result));
    buffer_free(&parameter);
}

static void test_rejects_ambiguous_contract_names(void **state) {
    (void) state;
    static const uint8_t embedded_nul[] = {'S', 'a', 'f', 'e', 0, 'H', 'i', 'd', 'd', 'e', 'n'};
    static const uint8_t control_char[] = {'S', 'a', 'f', 'e', '\n', 'H', 'i', 'd', 'd', 'e', 'n'};
    const struct {
        const uint8_t *name;
        size_t len;
    } cases[] = {
        {embedded_nul, sizeof(embedded_nul)},
        {control_char, sizeof(control_char)},
    };

    for (size_t i = 0U; i < sizeof(cases) / sizeof(cases[0]); i++) {
        test_buffer_t parameter = build_create_with_name(10U,
                                                         true,
                                                         0U,
                                                         false,
                                                         cases[i].name,
                                                         cases[i].len);
        create_smart_contract_stream_t stream;

        create_smart_contract_stream_init(&stream, parameter.len);
        assert_false(feed_in_chunks(&stream, &parameter, 3U));
        buffer_free(&parameter);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_small_create_and_hash),
        cmocka_unit_test(test_large_bytecode_and_abi),
        cmocka_unit_test(test_absent_and_empty_bytecode_match),
        cmocka_unit_test(test_rejects_duplicate_new_contract),
        cmocka_unit_test(test_rejects_truncation),
        cmocka_unit_test(test_rejects_ambiguous_contract_names),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
