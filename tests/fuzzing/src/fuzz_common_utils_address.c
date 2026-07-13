#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "base58.h"
#include "common_utils.h"
#include "cx.h"

#define GUARD_SIZE 8U

static void require(int condition) {
    if (!condition) {
        __builtin_trap();
    }
}

static void fill_guard(uint8_t guard[static GUARD_SIZE], uint8_t value) {
    memset(guard, value, GUARD_SIZE);
}

static void require_guard(const uint8_t guard[static GUARD_SIZE], uint8_t value) {
    for (size_t i = 0; i < GUARD_SIZE; i++) {
        require(guard[i] == value);
    }
}

static void make_payload25(const uint8_t address20[static ADDRESS_LENGTH],
                           uint8_t prefix,
                           uint8_t payload25[static TRON_ADDRESS_SIZE + 4]) {
    uint8_t digest[CX_SHA256_SIZE];

    payload25[0] = prefix;
    memcpy(payload25 + 1, address20, ADDRESS_LENGTH);
    require(cx_hash_sha256(payload25, TRON_ADDRESS_SIZE, digest, sizeof(digest)) == CX_OK);
    require(cx_hash_sha256(digest, sizeof(digest), digest, sizeof(digest)) == CX_OK);
    memcpy(payload25 + TRON_ADDRESS_SIZE, digest, 4);
}

static void test_output_boundaries(const uint8_t address20[static ADDRESS_LENGTH]) {
    struct guarded_output {
        uint8_t before[GUARD_SIZE];
        char value[TRON_BASE58CHECK_ADDRESS_SIZE + 2];
        uint8_t after[GUARD_SIZE];
    } output;

    for (size_t output_size = 0; output_size <= sizeof(output.value); output_size++) {
        fill_guard(output.before, 0xA5);
        memset(output.value, 0xCC, sizeof(output.value));
        fill_guard(output.after, 0x5A);

        bool ok = tronBase58FromBinary(address20, output.value, output_size);
        require(ok == (output_size >= TRON_BASE58CHECK_ADDRESS_SIZE + 1U));
        require_guard(output.before, 0xA5);
        require_guard(output.after, 0x5A);
        for (size_t i = output_size; i < sizeof(output.value); i++) {
            require((uint8_t) output.value[i] == 0xCC);
        }

        if (ok) {
            require(strnlen(output.value, sizeof(output.value)) ==
                    TRON_BASE58CHECK_ADDRESS_SIZE);
            require(output.value[TRON_BASE58CHECK_ADDRESS_SIZE] == '\0');
        }
    }

    require(!tronBase58FromBinary(NULL, output.value, sizeof(output.value)));
    require(!tronBase58FromBinary(address20, NULL, sizeof(output.value)));
}

static void test_round_trip(const uint8_t address20[static ADDRESS_LENGTH]) {
    char encoded[TRON_BASE58CHECK_ADDRESS_SIZE + 1];
    char encoded_again[TRON_BASE58CHECK_ADDRESS_SIZE + 1];
    char eth_hex[2 + ADDRESS_LENGTH * 2 + 1];
    uint8_t decoded20[ADDRESS_LENGTH];
    uint8_t decoded25[TRON_ADDRESS_SIZE + 4];
    uint8_t expected25[TRON_ADDRESS_SIZE + 4];

    require(tronBase58FromBinary(address20, encoded, sizeof(encoded)));
    require(encoded[0] == 'T');
    require(strlen(encoded) == TRON_BASE58CHECK_ADDRESS_SIZE);

    memset(decoded20, 0xA5, sizeof(decoded20));
    require(tronBase58ToBinary(encoded, decoded20));
    require(memcmp(decoded20, address20, sizeof(decoded20)) == 0);

    memset(decoded20, 0xA5, sizeof(decoded20));
    require(tronBase58ToBinaryLen(encoded, TRON_BASE58CHECK_ADDRESS_SIZE, decoded20));
    require(memcmp(decoded20, address20, sizeof(decoded20)) == 0);

    require(base58_decode(encoded,
                          TRON_BASE58CHECK_ADDRESS_SIZE,
                          decoded25,
                          sizeof(decoded25)) == (int) sizeof(decoded25));
    make_payload25(address20, 0x41, expected25);
    require(memcmp(decoded25, expected25, sizeof(decoded25)) == 0);
    require(base58_encode(decoded25,
                          sizeof(decoded25),
                          encoded_again,
                          TRON_BASE58CHECK_ADDRESS_SIZE) == TRON_BASE58CHECK_ADDRESS_SIZE);
    encoded_again[TRON_BASE58CHECK_ADDRESS_SIZE] = '\0';
    require(strcmp(encoded, encoded_again) == 0);

    eth_hex[0] = '0';
    eth_hex[1] = 'x';
    for (size_t i = 0; i < ADDRESS_LENGTH; i++) {
        eth_hex[2 + i * 2] = HEXDIGITS[address20[i] >> 4];
        eth_hex[2 + i * 2 + 1] = HEXDIGITS[address20[i] & 0x0F];
    }
    eth_hex[2 + ADDRESS_LENGTH * 2] = '\0';
    require(ethToTronBase58(eth_hex, encoded_again, sizeof(encoded_again)));
    require(strcmp(encoded, encoded_again) == 0);
    require(ethToTronBase58(eth_hex + 2, encoded_again, sizeof(encoded_again)));
    require(strcmp(encoded, encoded_again) == 0);
}

static void require_rejected_without_output(const char input[static TRON_BASE58CHECK_ADDRESS_SIZE],
                                            size_t input_len) {
    struct guarded_address {
        uint8_t before[GUARD_SIZE];
        uint8_t value[ADDRESS_LENGTH];
        uint8_t after[GUARD_SIZE];
    } output;

    fill_guard(output.before, 0x3C);
    memset(output.value, 0xC3, sizeof(output.value));
    fill_guard(output.after, 0x3C);
    require(!tronBase58ToBinaryLen(input, input_len, output.value));
    require_guard(output.before, 0x3C);
    require_guard(output.after, 0x3C);
    for (size_t i = 0; i < sizeof(output.value); i++) {
        require(output.value[i] == 0xC3);
    }
}

static void test_invalid_checksum_and_prefix(const uint8_t address20[static ADDRESS_LENGTH]) {
    uint8_t payload25[TRON_ADDRESS_SIZE + 4];
    char encoded[TRON_BASE58CHECK_ADDRESS_SIZE + 1];

    make_payload25(address20, 0x41, payload25);
    payload25[TRON_ADDRESS_SIZE] ^= 1U;
    require(base58_encode(payload25,
                          sizeof(payload25),
                          encoded,
                          TRON_BASE58CHECK_ADDRESS_SIZE) == TRON_BASE58CHECK_ADDRESS_SIZE);
    encoded[TRON_BASE58CHECK_ADDRESS_SIZE] = '\0';
    require_rejected_without_output(encoded, TRON_BASE58CHECK_ADDRESS_SIZE);

    make_payload25(address20, 0x42, payload25);
    require(base58_encode(payload25,
                          sizeof(payload25),
                          encoded,
                          TRON_BASE58CHECK_ADDRESS_SIZE) == TRON_BASE58CHECK_ADDRESS_SIZE);
    encoded[TRON_BASE58CHECK_ADDRESS_SIZE] = '\0';
    require_rejected_without_output(encoded, TRON_BASE58CHECK_ADDRESS_SIZE);

    require_rejected_without_output(encoded, TRON_BASE58CHECK_ADDRESS_SIZE - 1U);
    require_rejected_without_output(encoded, TRON_BASE58CHECK_ADDRESS_SIZE + 1U);
}

static void test_arbitrary_decode(const uint8_t *data, size_t size) {
    char input[TRON_BASE58CHECK_ADDRESS_SIZE + 1];
    uint8_t decoded[ADDRESS_LENGTH];
    char canonical[TRON_BASE58CHECK_ADDRESS_SIZE + 1];
    const size_t input_len = size < TRON_BASE58CHECK_ADDRESS_SIZE ? size
                                                                 : TRON_BASE58CHECK_ADDRESS_SIZE;

    if (input_len != 0U) {
        memcpy(input, data, input_len);
    }
    input[input_len] = '\0';
    memset(decoded, 0x7E, sizeof(decoded));

    bool ok = tronBase58ToBinaryLen(input, input_len, decoded);
    if (ok) {
        require(input_len == TRON_BASE58CHECK_ADDRESS_SIZE);
        require(tronBase58FromBinary(decoded, canonical, sizeof(canonical)));
        require(memcmp(canonical, input, TRON_BASE58CHECK_ADDRESS_SIZE) == 0);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t address20[ADDRESS_LENGTH] = {0};

    if (size != 0U) {
        for (size_t i = 0; i < sizeof(address20); i++) {
            address20[i] = data[i % size];
        }
    }

    test_output_boundaries(address20);
    test_round_trip(address20);
    test_invalid_checksum_and_prefix(address20);
    test_arbitrary_decode(data, size);
    return 0;
}
