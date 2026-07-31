#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "der_signature.h"

static void assert_rejected(const uint8_t *signature, size_t signature_length) {
    uint8_t out[ECDSA_RS_SIGNATURE_SIZE];
    memset(out, 0xA5, sizeof(out));

    assert_false(ecdsa_der_to_rs(signature, signature_length, out));
    for (size_t i = 0; i < sizeof(out); i++) {
        assert_int_equal(out[i], 0xA5);
    }
}

static void test_valid_fixed_width_signature(void **state) {
    (void) state;
    uint8_t signature[70] = {0x30, 0x44, 0x02, 0x20};
    uint8_t out[ECDSA_RS_SIGNATURE_SIZE];
    signature[4] = 0x01;
    memset(signature + 5, 0x11, 31);
    signature[36] = 0x02;
    signature[37] = 0x20;
    signature[38] = 0x02;
    memset(signature + 39, 0x22, 31);

    assert_true(ecdsa_der_to_rs(signature, sizeof(signature), out));
    assert_memory_equal(out, signature + 4, 32);
    assert_memory_equal(out + 32, signature + 38, 32);
}

static void test_valid_sign_protected_signature(void **state) {
    (void) state;
    uint8_t signature[72] = {0x30, 0x46, 0x02, 0x21, 0x00, 0x80};
    uint8_t out[ECDSA_RS_SIGNATURE_SIZE];
    memset(signature + 6, 0x11, 31);
    signature[37] = 0x02;
    signature[38] = 0x21;
    signature[39] = 0x00;
    signature[40] = 0x81;
    memset(signature + 41, 0x22, 31);

    assert_true(ecdsa_der_to_rs(signature, sizeof(signature), out));
    assert_memory_equal(out, signature + 5, 32);
    assert_memory_equal(out + 32, signature + 40, 32);
}

static void test_valid_short_integers_are_left_padded(void **state) {
    (void) state;
    static const uint8_t signature[] = {
        0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01, 0x02,
    };
    uint8_t out[ECDSA_RS_SIGNATURE_SIZE];

    assert_true(ecdsa_der_to_rs(signature, sizeof(signature), out));
    for (size_t i = 0; i < 31U; i++) {
        assert_int_equal(out[i], 0);
    }
    assert_int_equal(out[31], 1);
    for (size_t i = 32U; i < 62U; i++) {
        assert_int_equal(out[i], 0);
    }
    assert_int_equal(out[62], 1);
    assert_int_equal(out[63], 2);
}

static void test_rejects_bad_envelope(void **state) {
    (void) state;
    static const uint8_t valid[] = {
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
    };
    uint8_t malformed[sizeof(valid) + 1U];

    assert_rejected(NULL, sizeof(valid));
    assert_rejected(valid, sizeof(valid) - 1U);

    memcpy(malformed, valid, sizeof(valid));
    malformed[0] = 0x31;
    assert_rejected(malformed, sizeof(valid));

    memcpy(malformed, valid, sizeof(valid));
    malformed[1] = 0x05;
    assert_rejected(malformed, sizeof(valid));

    memcpy(malformed, valid, sizeof(valid));
    malformed[sizeof(valid)] = 0x00;
    malformed[1]++;
    assert_rejected(malformed, sizeof(malformed));
}

static void test_rejects_bad_integer_lengths(void **state) {
    (void) state;
    static const uint8_t zero_length[] = {
        0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01,
    };
    static const uint8_t truncated[] = {
        0x30, 0x06, 0x02, 0x02, 0x01, 0x02, 0x02, 0x01,
    };
    uint8_t oversized[41] = {0x30, 0x27, 0x02, 0x22};
    oversized[4] = 0x01;
    oversized[38] = 0x02;
    oversized[39] = 0x01;
    oversized[40] = 0x01;

    assert_rejected(zero_length, sizeof(zero_length));
    assert_rejected(truncated, sizeof(truncated));
    assert_rejected(oversized, sizeof(oversized));
}

static void test_rejects_noncanonical_integers(void **state) {
    (void) state;
    static const uint8_t negative[] = {
        0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01,
    };
    static const uint8_t redundant_zero[] = {
        0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01,
    };
    uint8_t wide_without_padding[40] = {0x30, 0x26, 0x02, 0x21};
    wide_without_padding[4] = 0x01;
    wide_without_padding[37] = 0x02;
    wide_without_padding[38] = 0x01;
    wide_without_padding[39] = 0x01;

    assert_rejected(negative, sizeof(negative));
    assert_rejected(redundant_zero, sizeof(redundant_zero));
    assert_rejected(wide_without_padding, sizeof(wide_without_padding));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_valid_fixed_width_signature),
        cmocka_unit_test(test_valid_sign_protected_signature),
        cmocka_unit_test(test_valid_short_integers_are_left_padded),
        cmocka_unit_test(test_rejects_bad_envelope),
        cmocka_unit_test(test_rejects_bad_integer_lengths),
        cmocka_unit_test(test_rejects_noncanonical_integers),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
