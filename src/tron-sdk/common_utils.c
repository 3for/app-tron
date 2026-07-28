/*******************************************************************************
 *   Ledger TRON App
 *   (c) 2026-2029 Ledger
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

#include <stdint.h>
#include <string.h>

#include "asset_info.h"
#include "base58.h"
#include "common_utils.h"
#include "lcx_ecfp.h"
#include "lcx_sha3.h"

static bool hex_char_to_nibble(char c, uint8_t *out) {
    if (c >= '0' && c <= '9') {
        *out = (uint8_t) (c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        *out = (uint8_t) (c - 'a' + 10);
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        *out = (uint8_t) (c - 'A' + 10);
        return true;
    }
    return false;
}

static bool hex_string_to_bytes_20(const char *hex, uint8_t out[static ADDRESS_LENGTH]) {
    for (size_t i = 0; i < ADDRESS_LENGTH; i++) {
        uint8_t high;
        uint8_t low;

        if (!hex_char_to_nibble(hex[2 * i], &high) || !hex_char_to_nibble(hex[2 * i + 1], &low)) {
            return false;
        }
        out[i] = (high << 4) | low;
    }
    return true;
}

int array_bytes_string(char *out, size_t outl, const void *value, size_t len) {
    if (outl <= 2) {
        // Need at least '0x' and 1 digit
        return -1;
    }
    if (strlcpy(out, "0x", outl) != 2) {
        goto err;
    }
    if (format_hex(value, len, out + 2, outl - 2) < 0) {
        goto err;
    }
    return 0;
err:
    *out = '\0';
    return -1;
}

uint64_t u64_from_BE(const uint8_t *in, uint8_t size) {
    uint8_t i = 0;
    uint64_t res = 0;

    while (i < size && i < sizeof(res)) {
        res <<= 8;
        res |= in[i];
        i++;
    }

    return res;
}

bool u64_to_string(uint64_t src, char *dst, uint8_t dst_size) {
    // Copy the numbers in ASCII format.
    uint8_t i = 0;
    do {
        // Checking `i + 1` to make sure we have enough space for '\0'.
        if (i + 1 >= dst_size) {
            return false;
        }
        dst[i] = src % 10 + '0';
        src /= 10;
        i++;
    } while (src);

    // Null terminate string
    dst[i] = '\0';

    // Revert the string
    i--;
    uint8_t j = 0;
    while (j < i) {
        char tmp = dst[i];
        dst[i] = dst[j];
        dst[j] = tmp;
        i--;
        j++;
    }
    return true;
}

bool uint256_to_decimal(const uint8_t *value, size_t value_len, char *out, size_t out_len) {
    if (value_len > INT256_LENGTH || out == NULL || (value == NULL && value_len != 0)) {
        // Reject oversized values and invalid buffers before touching memory.
        return false;
    }

    uint16_t n[16] = {0};
    // Copy and right-align the number
    if (value_len != 0) {
        memcpy((uint8_t *) n + INT256_LENGTH - value_len, value, value_len);
    }

    // Special case when value is 0
    if (allzeroes(n, INT256_LENGTH)) {
        if (out_len < 2) {
            // Not enough space to hold "0" and \0.
            return false;
        }
        strlcpy(out, "0", out_len);
        return true;
    }

    uint16_t *p = n;
    for (int i = 0; i < 16; i++) {
        n[i] = __builtin_bswap16(*p++);
    }
    if (out_len == 0) {
        return false;
    }

    // Reserve the last byte for the terminator while producing digits backwards.
    size_t pos = out_len - 1U;
    out[pos] = '\0';
    while (!allzeroes(n, sizeof(n))) {
        if (pos == 0) {
            return false;
        }
        pos -= 1;
        unsigned int carry = 0;
        for (int i = 0; i < 16; i++) {
            int rem = ((carry << 16) | n[i]) % 10;
            n[i] = ((carry << 16) | n[i]) / 10;
            carry = rem;
        }
        out[pos] = '0' + carry;
    }
    const size_t digits = (out_len - 1U) - pos;
    memmove(out, out + pos, digits);
    out[digits] = '\0';
    return true;
}

bool adjustDecimals(const char *src,
                    size_t srcLength,
                    char *target,
                    size_t targetLength,
                    uint8_t decimals) {
    size_t trailing_zeros = 0;
    size_t offset = 0;
    bool value_is_zero = true;

    if (src == NULL || target == NULL || srcLength == 0) {
        return false;
    }

    for (size_t i = 0; i < srcLength; i++) {
        if (src[i] != '0') {
            value_is_zero = false;
            break;
        }
    }
    if (value_is_zero) {
        if (targetLength < 2) {
            return false;
        }
        target[0] = '0';
        target[1] = '\0';
        return true;
    }

    // Only fractional zeroes are trimmed. Determine the final length before
    // writing so a buffer sized exactly for the normalized result succeeds.
    const size_t source_fractional_digits =
        decimals < srcLength ? decimals : srcLength;
    while (trailing_zeros < source_fractional_digits &&
           src[srcLength - 1U - trailing_zeros] == '0') {
        trailing_zeros++;
    }

    if (srcLength <= decimals) {
        const size_t leading_fractional_zeros = decimals - srcLength;
        const size_t source_digits = srcLength - trailing_zeros;
        const size_t output_length = 2U + leading_fractional_zeros + source_digits;

        if (targetLength <= output_length) {
            return false;
        }
        target[offset++] = '0';
        target[offset++] = '.';
        for (size_t i = 0; i < leading_fractional_zeros; i++) {
            target[offset++] = '0';
        }
        if (source_digits != 0) {
            memcpy(target + offset, src, source_digits);
            offset += source_digits;
        }
        target[offset] = '\0';
    } else {
        const size_t integer_digits = srcLength - decimals;
        const size_t fractional_digits = decimals - trailing_zeros;
        const size_t output_length =
            integer_digits + (fractional_digits == 0 ? 0U : 1U + fractional_digits);

        if (targetLength <= output_length) {
            return false;
        }
        memcpy(target, src, integer_digits);
        offset = integer_digits;
        if (fractional_digits != 0) {
            target[offset++] = '.';
            memcpy(target + offset, src + integer_digits, fractional_digits);
            offset += fractional_digits;
        }
        target[offset] = '\0';
    }
    return true;
}

// change "4.2 ENS" to "ENS 4.2"
bool amountToString(const uint8_t *amount,
                    size_t amount_size,
                    uint8_t decimals,
                    const char *ticker,
                    char *out_buffer,
                    size_t out_buffer_size) {
    uint8_t amount_len = 0;
    uint8_t ticker_len = 0;
    char raw_amount_buffer[100] = {0};

    memset(out_buffer, 0, out_buffer_size);

    // Convert the amount to decimal string first
    if (uint256_to_decimal(amount, amount_size, raw_amount_buffer, sizeof(raw_amount_buffer)) ==
        false) {
        PRINTF("uint256_to_decimal failed\n");
        return false;
    }
    // Adjust the decimal position, store the result in out_buffer
    amount_len = strnlen(raw_amount_buffer, sizeof(raw_amount_buffer));
    ticker_len = strnlen(ticker, MAX_TICKER_LEN);
    if (adjustDecimals(raw_amount_buffer, amount_len, out_buffer, out_buffer_size, decimals) ==
        false) {
        PRINTF("adjustDecimals failed\n");
        return false;
    }

    // out_buffer will contain the amount, a space and the ticker, ended with \0
    if ((strlen(out_buffer) + 1 + ticker_len + 1) > out_buffer_size) {
        PRINTF("Not enough space for ticker\n");
        return false;
    }
    // Append a space and the ticker to the out_buffer
    // strlcat cannot fail here as we checked boundaries above
    strlcat(out_buffer, " ", out_buffer_size);
    strlcat(out_buffer, ticker, out_buffer_size);

    return true;
}

void getEthAddressFromRawKey(const uint8_t raw_pubkey[static 65],
                             uint8_t out[static ADDRESS_LENGTH]) {
    uint8_t hashAddress[CX_KECCAK_256_SIZE];
    CX_ASSERT(cx_keccak_256_hash(raw_pubkey + 1, 64, hashAddress));
    memmove(out, hashAddress + 12, ADDRESS_LENGTH);
}

bool getEthAddressStringFromBinary(const uint8_t *address,
                                   char out[static(ADDRESS_LENGTH * 2) + 1],
                                   uint64_t chainId) {
    // save some precious stack space
    union locals_union {
        uint8_t hashChecksum[INT256_LENGTH];
        uint8_t tmp[51];
    } locals_union;

    uint8_t i;
    bool eip1191 = false;
    uint32_t offset = 0;
    switch (chainId) {
        case 30:
        case 31:
            eip1191 = true;
            break;
    }
    if (eip1191) {
        if (!u64_to_string(chainId, (char *) locals_union.tmp, sizeof(locals_union.tmp))) {
            return false;
        }
        offset = strnlen((char *) locals_union.tmp, sizeof(locals_union.tmp));
        strlcat((char *) locals_union.tmp + offset, "0x", sizeof(locals_union.tmp) - offset);
        offset = strnlen((char *) locals_union.tmp, sizeof(locals_union.tmp));
    }
    for (i = 0; i < 20; i++) {
        uint8_t digit = address[i];
        locals_union.tmp[offset + 2 * i] = HEXDIGITS[(digit >> 4) & 0x0f];
        locals_union.tmp[offset + 2 * i + 1] = HEXDIGITS[digit & 0x0f];
    }
    if (cx_keccak_256_hash(locals_union.tmp, offset + 40, locals_union.hashChecksum) != CX_OK) {
        return false;
    }

    for (i = 0; i < 40; i++) {
        uint8_t digit = address[i / 2];
        if ((i % 2) == 0) {
            digit = (digit >> 4) & 0x0f;
        } else {
            digit = digit & 0x0f;
        }
        if (digit < 10) {
            out[i] = HEXDIGITS[digit];
        } else {
            int v = (locals_union.hashChecksum[i / 2] >> (4 * (1 - i % 2))) & 0x0f;
            if (v >= 8) {
                out[i] = HEXDIGITS[digit] - 'a' + 'A';
            } else {
                out[i] = HEXDIGITS[digit];
            }
        }
    }
    out[ADDRESS_LENGTH * 2] = '\0';

    return true;
}

bool getEthDisplayableAddress(const uint8_t *in, char *out, size_t out_len, uint64_t chainId) {
    if (out_len < 43) {
        strlcpy(out, "ERROR", out_len);
        return false;
    }
    out[0] = '0';
    out[1] = 'x';
    if (!getEthAddressStringFromBinary(in, out + 2, chainId)) {
        strlcpy(out, "ERROR", out_len);
        return false;
    }

    return true;
}

bool tronBase58FromBinary(const uint8_t *eth20, char *out58, size_t out58_len) {
    uint8_t tronAddr[TRON_ADDRESS_SIZE];
    uint8_t sha256[CX_SHA256_SIZE];
    uint8_t addchecksum[TRON_ADDRESS_SIZE + 4];

    if (eth20 == NULL || out58 == NULL || out58_len < (TRON_BASE58CHECK_ADDRESS_SIZE + 1)) {
        return false;
    }
    out58[0] = '\0';

    tronAddr[0] = TRON_MAINNET_ADDRESS_PREFIX;
    memcpy(tronAddr + 1, eth20, ADDRESS_LENGTH);

    cx_hash_sha256(tronAddr, sizeof(tronAddr), sha256, sizeof(sha256));
    cx_hash_sha256(sha256, sizeof(sha256), sha256, sizeof(sha256));

    memcpy(addchecksum, tronAddr, sizeof(tronAddr));
    memcpy(addchecksum + sizeof(tronAddr), sha256, 4);

    if (base58_encode(addchecksum, sizeof(addchecksum), out58, TRON_BASE58CHECK_ADDRESS_SIZE) < 0) {
        out58[0] = '\0';
        return false;
    }
    out58[TRON_BASE58CHECK_ADDRESS_SIZE] = '\0';
    return true;
}

bool tronBase58ToBinaryLen(const char *in, size_t len, uint8_t *out20) {
    // Decoded TRON address: 0x41 prefix + 20-byte address + 4-byte checksum.
    uint8_t decoded[TRON_ADDRESS_SIZE + 4];
    uint8_t sha256[CX_SHA256_SIZE];

    if (in == NULL || out20 == NULL) {
        return false;
    }

    // TRON Base58Check addresses are a fixed 34 characters ("T...").
    if (len != TRON_BASE58CHECK_ADDRESS_SIZE) {
        return false;
    }

    // base58_decode does raw Base58 (no checksum verification); it left-aligns the
    // output and returns the byte count.
    if (base58_decode(in, len, decoded, sizeof(decoded)) != (int) sizeof(decoded)) {
        return false;
    }

    // Must be a mainnet address (0x41 prefix).
    if (decoded[0] != 0x41) {
        return false;
    }

    // Verify the Base58Check checksum: first 4 bytes of the double SHA-256 over the
    // 21-byte (prefix + address) payload must match the trailing 4 bytes.
    cx_hash_sha256(decoded, TRON_ADDRESS_SIZE, sha256, sizeof(sha256));
    cx_hash_sha256(sha256, sizeof(sha256), sha256, sizeof(sha256));
    if (memcmp(sha256, decoded + TRON_ADDRESS_SIZE, 4) != 0) {
        return false;
    }

    memcpy(out20, decoded + 1, ADDRESS_LENGTH);
    return true;
}

bool tronBase58ToBinary(const char *in, uint8_t *out20) {
    if (in == NULL) {
        return false;
    }
    return tronBase58ToBinaryLen(in, strnlen(in, TRON_BASE58CHECK_ADDRESS_SIZE + 1), out20);
}

bool ethToTronBase58(const char *ethAddress, char *out58, size_t out58_len) {
    uint8_t eth20[ADDRESS_LENGTH];
    const char *hex;

    if (ethAddress == NULL) {
        return false;
    }

    if (ethAddress[0] == '0' && (ethAddress[1] == 'x' || ethAddress[1] == 'X')) {
        hex = ethAddress + 2;
    } else {
        hex = ethAddress;
    }

    if (strnlen(hex, (ADDRESS_LENGTH * 2) + 1) != (ADDRESS_LENGTH * 2)) {
        return false;
    }
    if (!hex_string_to_bytes_20(hex, eth20)) {
        return false;
    }

    return tronBase58FromBinary(eth20, out58, out58_len);
}

int allzeroes(const void *buf, size_t n) {
    uint8_t *p = (uint8_t *) buf;
    for (size_t i = 0; i < n; ++i) {
        if (p[i]) {
            return 0;
        }
    }
    return 1;
}

int ismaxint(const uint8_t *buf, int n) {
    for (int i = 0; i < n; ++i) {
        if (buf[i] != 0xff) {
            return 0;
        }
    }
    return 1;
}
