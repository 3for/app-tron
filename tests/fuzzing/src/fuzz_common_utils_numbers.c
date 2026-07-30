#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "asset_info.h"
#include "common_utils.h"
#include "uint128.h"
#include "uint256.h"
#include "utils.h"

#define DECIMAL_BUFFER_SIZE 80U
#define AMOUNT_BUFFER_SIZE  384U
#define GUARD_SIZE          8U

static void require(int condition) {
    if (!condition) {
        __builtin_trap();
    }
}

static void require_bytes(const uint8_t *bytes, size_t size, uint8_t expected) {
    for (size_t i = 0; i < size; i++) {
        require(bytes[i] == expected);
    }
}

static void require_untouched_tail(const char *buffer, size_t used_size, size_t buffer_size) {
    for (size_t i = used_size; i < buffer_size; i++) {
        require((uint8_t) buffer[i] == 0xCC);
    }
}

static void test_reverse_string(const uint8_t *data, size_t size) {
    char value[DECIMAL_BUFFER_SIZE];
    char original[DECIMAL_BUFFER_SIZE];
    const size_t length = size < sizeof(value) ? size : sizeof(value);
    char single = 'x';

    /* Edge cases must be no-ops, including a NULL buffer with no work to do. */
    reverseString(NULL, 0U);
    reverseString(NULL, 1U);
    reverseString(&single, 0U);
    reverseString(&single, 1U);
    require(single == 'x');

    if (length != 0U) {
        memcpy(value, data, length);
        memcpy(original, data, length);
    }
    reverseString(value, (uint32_t) length);
    reverseString(value, (uint32_t) length);
    require(memcmp(value, original, length) == 0);
}

/* Independent base-256 long division reference, deliberately not using uint128/uint256. */
static void reference_decimal(const uint8_t *value,
                              size_t value_len,
                              char out[DECIMAL_BUFFER_SIZE]) {
    uint8_t work[INT256_LENGTH] = {0};
    char reversed[DECIMAL_BUFFER_SIZE];
    size_t digits = 0;
    size_t first = 0;

    require(value_len <= sizeof(work));
    if (value_len != 0U) {
        memcpy(work + sizeof(work) - value_len, value, value_len);
    }
    while (first < sizeof(work) && work[first] == 0U) {
        first++;
    }
    if (first == sizeof(work)) {
        memcpy(out, "0", 2);
        return;
    }

    while (first < sizeof(work)) {
        unsigned int remainder = 0;

        for (size_t i = first; i < sizeof(work); i++) {
            const unsigned int dividend = remainder * 256U + work[i];
            work[i] = (uint8_t) (dividend / 10U);
            remainder = dividend % 10U;
        }
        require(digits + 1U < sizeof(reversed));
        reversed[digits++] = (char) ('0' + remainder);
        while (first < sizeof(work) && work[first] == 0U) {
            first++;
        }
    }

    for (size_t i = 0; i < digits; i++) {
        out[i] = reversed[digits - 1U - i];
    }
    out[digits] = '\0';
}

static void reference_signed_decimal(const uint8_t *value,
                                     size_t value_len,
                                     char out[DECIMAL_BUFFER_SIZE]) {
    uint8_t magnitude[INT256_LENGTH];

    require(value_len != 0U && value_len <= sizeof(magnitude));
    memcpy(magnitude, value, value_len);
    if ((value[0] & 0x80U) == 0U) {
        reference_decimal(value, value_len, out);
        return;
    }

    for (size_t i = 0; i < value_len; i++) {
        magnitude[i] = (uint8_t) ~magnitude[i];
    }
    for (size_t i = value_len; i > 0U; i--) {
        magnitude[i - 1U]++;
        if (magnitude[i - 1U] != 0U) {
            break;
        }
    }
    out[0] = '-';
    reference_decimal(magnitude, value_len, out + 1);
}

static void test_uint128_decimal(const uint8_t value[static INT128_LENGTH]) {
    struct guarded_decimal {
        uint8_t before[GUARD_SIZE];
        char value[DECIMAL_BUFFER_SIZE];
        uint8_t after[GUARD_SIZE];
    } output;
    uint128_t number;
    char expected[DECIMAL_BUFFER_SIZE];

    readu128BE(value, &number);
    reference_decimal(value, INT128_LENGTH, expected);
    const size_t required = strlen(expected) + 1U;
    const uint32_t sizes[] = {0U, (uint32_t) (required - 1U), (uint32_t) required,
                              DECIMAL_BUFFER_SIZE};

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        memset(output.before, 0xA1, sizeof(output.before));
        memset(output.value, 0xCC, sizeof(output.value));
        memset(output.after, 0x1A, sizeof(output.after));

        bool ok = tostring128(&number, 10, output.value, sizes[i]);
        require(ok == (sizes[i] >= required));
        require_bytes(output.before, sizeof(output.before), 0xA1);
        require_bytes(output.after, sizeof(output.after), 0x1A);
        require_untouched_tail(output.value, sizes[i], sizeof(output.value));
        if (ok) {
            require(strcmp(output.value, expected) == 0);
        }
    }

    reference_signed_decimal(value, INT128_LENGTH, expected);
    const size_t signed_required = strlen(expected) + 1U;
    const uint32_t signed_sizes[] = {0U,
                                     (uint32_t) (signed_required - 1U),
                                     (uint32_t) signed_required,
                                     DECIMAL_BUFFER_SIZE};
    for (size_t i = 0; i < sizeof(signed_sizes) / sizeof(signed_sizes[0]); i++) {
        memset(output.before, 0xA1, sizeof(output.before));
        memset(output.value, 0xCC, sizeof(output.value));
        memset(output.after, 0x1A, sizeof(output.after));

        bool ok = tostring128_signed(&number, 10, output.value, signed_sizes[i]);
        require(ok == (signed_sizes[i] >= signed_required));
        require_bytes(output.before, sizeof(output.before), 0xA1);
        require_bytes(output.after, sizeof(output.after), 0x1A);
        require_untouched_tail(output.value, signed_sizes[i], sizeof(output.value));
        if (ok) {
            require(strcmp(output.value, expected) == 0);
        }
    }
}

static void test_uint256_decimal(const uint8_t value[static INT256_LENGTH]) {
    struct guarded_decimal {
        uint8_t before[GUARD_SIZE];
        char value[DECIMAL_BUFFER_SIZE];
        uint8_t after[GUARD_SIZE];
    } output;
    uint256_t number;
    char expected[DECIMAL_BUFFER_SIZE];

    readu256BE(value, &number);
    reference_decimal(value, INT256_LENGTH, expected);
    const size_t required = strlen(expected) + 1U;
    const uint32_t sizes[] = {0U, (uint32_t) (required - 1U), (uint32_t) required,
                              DECIMAL_BUFFER_SIZE};

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        memset(output.before, 0xB2, sizeof(output.before));
        memset(output.value, 0xCC, sizeof(output.value));
        memset(output.after, 0x2B, sizeof(output.after));

        bool ok = tostring256(&number, 10, output.value, sizes[i]);
        require(ok == (sizes[i] >= required));
        require_bytes(output.before, sizeof(output.before), 0xB2);
        require_bytes(output.after, sizeof(output.after), 0x2B);
        require_untouched_tail(output.value, sizes[i], sizeof(output.value));
        if (ok) {
            require(strcmp(output.value, expected) == 0);
        }
    }

    reference_signed_decimal(value, INT256_LENGTH, expected);
    const size_t signed_required = strlen(expected) + 1U;
    const uint32_t signed_sizes[] = {0U,
                                     (uint32_t) (signed_required - 1U),
                                     (uint32_t) signed_required,
                                     DECIMAL_BUFFER_SIZE};
    for (size_t i = 0; i < sizeof(signed_sizes) / sizeof(signed_sizes[0]); i++) {
        memset(output.before, 0xB2, sizeof(output.before));
        memset(output.value, 0xCC, sizeof(output.value));
        memset(output.after, 0x2B, sizeof(output.after));

        bool ok = tostring256_signed(&number, 10, output.value, signed_sizes[i]);
        require(ok == (signed_sizes[i] >= signed_required));
        require_bytes(output.before, sizeof(output.before), 0xB2);
        require_bytes(output.after, sizeof(output.after), 0x2B);
        require_untouched_tail(output.value, signed_sizes[i], sizeof(output.value));
        if (ok) {
            require(strcmp(output.value, expected) == 0);
        }
    }
}

static void test_common_uint256_decimal(const uint8_t value[static INT256_LENGTH],
                                        size_t value_len,
                                        size_t random_output_size) {
    struct guarded_decimal {
        uint8_t before[GUARD_SIZE];
        char value[DECIMAL_BUFFER_SIZE];
        uint8_t after[GUARD_SIZE];
    } output;
    char expected[DECIMAL_BUFFER_SIZE];
    size_t required = 0;
    size_t sizes[4];

    if (value_len <= INT256_LENGTH) {
        reference_decimal(value, value_len, expected);
        required = strlen(expected) + 1U;
    }
    sizes[0] = 0U;
    sizes[1] = value_len <= INT256_LENGTH ? required - 1U : DECIMAL_BUFFER_SIZE;
    sizes[2] = value_len <= INT256_LENGTH ? required : DECIMAL_BUFFER_SIZE;
    sizes[3] = random_output_size % (DECIMAL_BUFFER_SIZE + 1U);

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        memset(output.before, 0xD4, sizeof(output.before));
        memset(output.value, 0xCC, sizeof(output.value));
        memset(output.after, 0x4D, sizeof(output.after));

        bool ok = uint256_to_decimal(value, value_len, output.value, sizes[i]);
        const bool expected_ok = value_len <= INT256_LENGTH && sizes[i] >= required;
        require(ok == expected_ok);
        require_bytes(output.before, sizeof(output.before), 0xD4);
        require_bytes(output.after, sizeof(output.after), 0x4D);
        require_untouched_tail(output.value, sizes[i], sizeof(output.value));
        if (ok) {
            require(strcmp(output.value, expected) == 0);
        }
    }
}

static void reference_adjust_decimals(const char *raw,
                                      uint8_t decimals,
                                      char out[AMOUNT_BUFFER_SIZE]) {
    const size_t raw_len = strlen(raw);
    size_t offset = 0;
    size_t fractional_start = 0;

    if (strcmp(raw, "0") == 0) {
        memcpy(out, "0", 2);
        return;
    }
    if (raw_len <= decimals) {
        out[offset++] = '0';
        out[offset++] = '.';
        for (size_t i = 0; i < (size_t) decimals - raw_len; i++) {
            out[offset++] = '0';
        }
        fractional_start = offset;
        memcpy(out + offset, raw, raw_len);
        offset += raw_len;
    } else {
        const size_t integer_len = raw_len - decimals;
        memcpy(out, raw, integer_len);
        offset = integer_len;
        if (decimals != 0U) {
            out[offset++] = '.';
        }
        fractional_start = offset;
        memcpy(out + offset, raw + integer_len, decimals);
        offset += decimals;
    }

    while (offset > fractional_start && out[offset - 1U] == '0') {
        offset--;
    }
    if (offset != 0U && out[offset - 1U] == '.') {
        offset--;
    }
    out[offset] = '\0';
}

static void test_amount_case(const uint8_t *amount,
                             uint8_t amount_len,
                             uint8_t decimals,
                             const char *ticker,
                             size_t random_output_size) {
    struct guarded_amount {
        uint8_t before[GUARD_SIZE];
        char value[AMOUNT_BUFFER_SIZE];
        uint8_t after[GUARD_SIZE];
    } output;
    char raw[DECIMAL_BUFFER_SIZE];
    char adjusted[AMOUNT_BUFFER_SIZE];
    char expected[AMOUNT_BUFFER_SIZE];
    size_t required = 0;
    size_t sizes[4];
    const bool valid_amount = amount_len <= INT256_LENGTH;

    if (valid_amount) {
        reference_decimal(amount, amount_len, raw);
        reference_adjust_decimals(raw, decimals, adjusted);
        require(strlen(adjusted) + 1U + strlen(ticker) + 1U <= sizeof(expected));
        memcpy(expected, adjusted, strlen(adjusted));
        expected[strlen(adjusted)] = ' ';
        strcpy(expected + strlen(adjusted) + 1U, ticker);
        required = strlen(expected) + 1U;
    }

    sizes[0] = 0U;
    sizes[1] = valid_amount ? required - 1U : AMOUNT_BUFFER_SIZE;
    sizes[2] = valid_amount ? required : AMOUNT_BUFFER_SIZE;
    sizes[3] = random_output_size % (AMOUNT_BUFFER_SIZE + 1U);

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        memset(output.before, 0xE5, sizeof(output.before));
        memset(output.value, 0xCC, sizeof(output.value));
        memset(output.after, 0x5E, sizeof(output.after));

        bool ok = amountToString(amount,
                                 amount_len,
                                 decimals,
                                 ticker,
                                 output.value,
                                 sizes[i]);
        const bool expected_ok = valid_amount && sizes[i] >= required;
        require(ok == expected_ok);
        require_bytes(output.before, sizeof(output.before), 0xE5);
        require_bytes(output.after, sizeof(output.after), 0x5E);
        require_untouched_tail(output.value, sizes[i], sizeof(output.value));
        if (ok) {
            require(strcmp(output.value, expected) == 0);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t value[INT256_LENGTH] = {0};
    char ticker[MAX_TICKER_LEN + 1];
    char max_ticker[MAX_TICKER_LEN];
    const size_t copied = size < sizeof(value) ? size : sizeof(value);
    const uint8_t amount_len = size > 32U ? (uint8_t) (data[32] % 34U) : (uint8_t) copied;
    const uint8_t decimals = size > 33U ? data[33] : (uint8_t) size;
    const size_t ticker_len = size > 34U ? data[34] % (MAX_TICKER_LEN + 1U) : 0U;
    const size_t random_output_size = size > 35U ? data[35] : size;

    if (copied != 0U) {
        memcpy(value, data, copied);
    }
    for (size_t i = 0; i < ticker_len; i++) {
        const uint8_t byte = size == 0U ? (uint8_t) i : data[i % size];
        ticker[i] = (char) ('A' + byte % 26U);
    }
    ticker[ticker_len] = '\0';
    memset(max_ticker, 'Z', sizeof(max_ticker) - 1U);
    max_ticker[sizeof(max_ticker) - 1U] = '\0';

    test_reverse_string(data, size);
    test_uint128_decimal(value);
    test_uint256_decimal(value);
    test_common_uint256_decimal(value, amount_len, random_output_size);
    test_amount_case(value, amount_len, decimals, ticker, random_output_size);
    test_amount_case(value,
                     amount_len,
                     decimals,
                     max_ticker,
                     AMOUNT_BUFFER_SIZE - 1U - random_output_size);
    test_amount_case(value, INT256_LENGTH, 0U, ticker, random_output_size);
    test_amount_case(value,
                     INT256_LENGTH,
                     UINT8_MAX,
                     max_ticker,
                     AMOUNT_BUFFER_SIZE - 1U - random_output_size);
    return 0;
}
