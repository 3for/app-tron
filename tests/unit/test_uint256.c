/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2023 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "uint256.h"

#define CANARY 0xa5u

static void test_uint128_requires_terminator_space(void) {
    uint128_t number = {.elements = {UINT64_MAX, UINT64_MAX}};
    struct {
        uint8_t before;
        char output[39];
        uint8_t after;
    } exact = {.before = CANARY, .output = {0}, .after = CANARY};
    char output[40] = {0};

    const bool exact_fit_succeeded = tostring128(&number, 10, exact.output, sizeof(exact.output));
    assert(exact.before == CANARY);
    assert(exact.after == CANARY);
    assert(!exact_fit_succeeded);
    assert(exact.output[0] == '\0');

    assert(tostring128(&number, 10, output, sizeof(output)));
    assert(strcmp(output, "340282366920938463463374607431768211455") == 0);
}

static void test_reported_uint256_value_requires_terminator_space(void) {
    const uint8_t encoded[] = {
        0x01,
        0x43,
        0x1e,
        0x0f,
        0xae,
        0x6d,
        0x72,
        0x17,
        0xca,
        0xa0,
        0x00,
        0x00,
        0x00,
    };
    uint256_t number;
    struct {
        uint8_t before;
        char output[30];
        uint8_t after;
    } exact = {.before = CANARY, .output = {0}, .after = CANARY};
    char output[31] = {0};

    assert(convertUint256BE(encoded, sizeof(encoded), &number));
    const bool exact_fit_succeeded = tostring256(&number, 10, exact.output, sizeof(exact.output));
    assert(exact.before == CANARY);
    assert(exact.after == CANARY);
    assert(!exact_fit_succeeded);
    assert(exact.output[0] == '\0');

    assert(tostring256(&number, 10, output, sizeof(output)));
    assert(strcmp(output, "100000000000000000000000000000") == 0);
}

static void test_swap_capacity_accepts_maximum_amount(void) {
    const uint8_t encoded[16] = {
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
    };
    uint256_t number;
    char output[50] = {0};

    assert(convertUint256BE(encoded, sizeof(encoded), &number));
    assert(tostring256(&number, 10, output, sizeof(output)));
    assert(strcmp(output, "340282366920938463463374607431768211455") == 0);
}

static void test_uint256_requires_terminator_space(void) {
    const uint8_t encoded[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    uint256_t number;
    struct {
        uint8_t before;
        char output[78];
        uint8_t after;
    } exact = {.before = CANARY, .output = {0}, .after = CANARY};
    char output[79] = {0};

    assert(convertUint256BE(encoded, sizeof(encoded), &number));
    const bool exact_fit_succeeded = tostring256(&number, 10, exact.output, sizeof(exact.output));
    assert(exact.before == CANARY);
    assert(exact.after == CANARY);
    assert(!exact_fit_succeeded);
    assert(exact.output[0] == '\0');

    assert(tostring256(&number, 10, output, sizeof(output)));
    assert(
        strcmp(output,
               "115792089237316195423570985008687907853269984665640564039457584007913129639935") ==
        0);
}

static void test_invalid_output_buffers_are_rejected(void) {
    uint256_t number = {0};
    char output = 'x';

    assert(!tostring256(&number, 10, &output, 0));
    assert(output == 'x');
    assert(!tostring256(&number, 10, &output, 1));
    assert(output == 'x');
    assert(!tostring256(NULL, 10, &output, 1));
    assert(!tostring256(&number, 10, NULL, 1));
}

int main(void) {
    test_reported_uint256_value_requires_terminator_space();
    test_uint128_requires_terminator_space();
    test_swap_capacity_accepts_maximum_amount();
    test_uint256_requires_terminator_space();
    test_invalid_output_buffers_are_rejected();
    return 0;
}
