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

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "cx.h"
#include "format.h"
#include "os.h"

// --8<-- [start:common_utils]

// Number of decimal places in 1 Ether (or similar cryptocurrency) when
// represented in Wei.
#define WEI_TO_ETHER 18

#define SUN_TO_TRX 6

// The standard length of an Ethereum address
#define ADDRESS_LENGTH 20

// Prefix of a 21-byte TRON mainnet address.
#define TRON_MAINNET_ADDRESS_PREFIX 0x41U

// The standard length of an TRON Ethereum-format address
#define TRON_ADDRESS_SIZE 21
// The standard length of a TRON Base58Check address string (without '\0')
#define TRON_BASE58CHECK_ADDRESS_SIZE 34

#define TRX_DECIMALS                  6
#define MAX_TRC10_PRECISION           6
#define MIN_TRC10_TOKEN_ID            1000000
#define MAX_URL_SIZE                  256
#define MAX_TRC10_TOKEN_ID_LENGTH     19
#define MAX_TRC10_ASSET_NAME_LENGTH   32
// Maximum formatted TRC-10 label: "<32-byte name>[<19-digit id>]" plus NUL.
#define TOKEN_DISPLAY_BUFFER_SIZE     \
    (MAX_TRC10_ASSET_NAME_LENGTH + MAX_TRC10_TOKEN_ID_LENGTH + 3)
#define MAX_ACCOUNT_NAME_SIZE         200
#define MAX_ACCOUNT_NAME_DISPLAY_SIZE (2 + MAX_ACCOUNT_NAME_SIZE * 2 + 1)
#define MIN_ACCOUNT_ID_SIZE           8
#define MAX_ACCOUNT_ID_SIZE           32
#define MAX_PROPOSAL_PARAMETERS       80

// The length of a 128-bit integer in bytes
#define INT128_LENGTH 16

// The length of a 256-bit integer in bytes.
#define INT256_LENGTH 32

// The byte size of a Keccak-256 hash.
#define KECCAK256_HASH_BYTESIZE 32

// A TRON transaction ID is conventionally rendered as 64 lowercase hexadecimal
// characters, without an Ethereum-style "0x" prefix.
#define TRON_TXID_HEX_SIZE (KECCAK256_HASH_BYTESIZE * 2U)

// Hexadecimal digits for formatting and parsing purposes.
static const char HEXDIGITS[] = "0123456789abcdef";

// Computes the number of elements in an array.
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

/**
 * @brief Converts a binary value to a hexadecimal string representation.
 *
 * This function formats a binary value (represented by `value`) into a
 * hexadecimal string, prefixed with '0x'. The resulting string is stored in the
 * `out` buffer. The buffer should be large enough to accommodate the '0x'
 * prefix and the hexadecimal representation of the binary value.
 *
 * @param out A pointer to the buffer where the hexadecimal string will be
 * stored.
 * @param outl The length of the output buffer.
 * @param value A pointer to the binary value to be converted.
 * @param len The length of the binary value.
 * @return 0 on success, or -1 if an error occurs (e.g., buffer too small).
 */
int array_bytes_string(char *out, size_t outl, const void *value, size_t len);

/**
 * @brief Formats a TRON transaction ID using its canonical display form.
 *
 * @param out Output buffer for 64 lowercase hexadecimal characters and NUL.
 * @param out_len Size of the output buffer.
 * @param txid The 32-byte transaction ID.
 * @return true on success, false for invalid pointers or an undersized buffer.
 */
bool format_tron_txid(char *out,
                      size_t out_len,
                      const uint8_t txid[static KECCAK256_HASH_BYTESIZE]);

/**
 * @brief Converts a big-endian byte array to a 64-bit unsigned integer.
 *
 * This function interprets the byte array `in` as a big-endian number and
 * converts it to a 64-bit unsigned integer. The conversion stops after `size`
 * bytes or when the input array has been fully processed.
 *
 * @param in A pointer to the byte array representing the big-endian number.
 * @param size The number of bytes to consider from the byte array.
 * @return The 64-bit unsigned integer representation of the byte array.
 */
uint64_t u64_from_BE(const uint8_t *in, uint8_t size);

/**
 * @brief Converts a 64-bit unsigned integer to a string.
 *
 * This function converts a 64-bit unsigned integer (`src`) to its decimal
 * string representation, storing the result in the `dst` buffer. The conversion
 * ensures that the resulting string is null-terminated and the buffer size
 * (`dst_size`) is sufficient to hold the result and the null terminator.
 *
 * @param src The 64-bit unsigned integer to convert.
 * @param dst A pointer to the buffer where the decimal string will be stored.
 * @param dst_size The size of the output buffer.
 * @return true if the conversion was successful and the output buffer contains
 * the resulting string, false if the buffer is too small or an error occurs.
 */
bool u64_to_string(uint64_t src, char *dst, size_t dst_size);

/**
 * @brief Converts a uint256 value to its decimal string representation.
 *
 * This function takes a uint256 value represented as a byte array, converts it
 * to a decimal string, and stores the result in the provided `out` buffer.
 * Leading zeros in the resulting decimal string are removed.
 *
 * @param value A pointer to the byte array representing the uint256 value.
 * @param value_len The length of the byte array `value`.
 * @param out A pointer to the buffer where the decimal string representation
 * will be stored.
 * @param out_len The length of the output buffer `out`.
 */
bool uint256_to_decimal(const uint8_t *value, size_t value_len, char *out, size_t out_len);

/**
 * @brief Converts an amount to its string representation with decimals and
 * ticker.
 *
 * This function takes a numeric amount represented as a byte array, converts it
 * to a decimal string, adjusts its decimal position according to the specified
 * number of decimals, and appends a ticker. The result is stored in the
 * `out_buffer`.
 *
 * @param amount A pointer to the byte array representing the amount.
 * @param amount_size The size of the amount byte array.
 * @param decimals The number of decimals to adjust to.
 * @param ticker A pointer to the ticker string to append to the amount.
 * @param out_buffer A pointer to the buffer where the resulting string will be
 * stored.
 * @param out_buffer_size The size of the output buffer.
 * @return true if the conversion and formatting were successful, false if the
 * output buffer is too small or an error occurs.
 */
bool amountToString(const uint8_t *amount,
                    size_t amount_len,
                    uint8_t decimals,
                    const char *ticker,
                    char *out_buffer,
                    size_t out_buffer_size);

/**
 * @brief Adjusts the decimal position of a numeric string based on a specified
 * number of decimals.
 *
 * This function takes a numeric string `src` and adjusts its decimal position
 * according to the specified number of `decimals`, storing the result in the
 * `target` buffer. If the `src` string is shorter than the number of decimals,
 * leading zeros are added. Trailing zeros are removed from the result.
 *
 * @param src A pointer to the source numeric string.
 * @param srcLength The length of the source string.
 * @param target A pointer to the buffer where the adjusted string will be
 * stored.
 * @param targetLength The length of the target buffer.
 * @param decimals The number of decimals to adjust to.
 * @return true if the adjustment was successful and the target buffer contains
 * the resulting string, false if the target buffer is too small or an error
 * occurs.
 */
bool adjustDecimals(const char *src,
                    size_t srcLength,
                    char *target,
                    size_t targetLength,
                    uint8_t decimals);

/**
 * @brief Computes the Ethereum address from a raw public key.
 *
 * This function takes a 65-byte raw public key, computes its Keccak-256 hash,
 * and extracts the last 20 bytes as the Ethereum address.
 *
 * @param raw_pubkey A pointer to the raw public key (65 bytes).
 * @param out A pointer to the buffer where the 20-byte Ethereum address will be
 * stored.
 */
void getEthAddressFromRawKey(const uint8_t raw_pubkey[static 65],
                             uint8_t out[static ADDRESS_LENGTH]);


/**
 * @brief Converts a binary Ethereum address to its checksum string
 * representation.
 *
 * This function converts a binary Ethereum address to a hexadecimal string with
 * EIP-55 checksum. It supports EIP-1191 checksumming for specific chain IDs.
 *
 * @param address A pointer to the binary Ethereum address (20 bytes).
 * @param out A pointer to the buffer where the checksum string representation
 * will be stored. The buffer must be at least (ADDRESS_LENGTH * 2) + 1 bytes
 * long.
 * @param chainId The chain ID to be used for EIP-1191 checksum (if applicable).
 * @return true if the conversion was successful and the output buffer contains
 * the resulting string, false if an error occurs.
 */
bool getEthAddressStringFromBinary(const uint8_t *address,
                                   char out[static(ADDRESS_LENGTH * 2) + 1],
                                   uint64_t chainId);

/**
 * @brief Converts a binary Ethereum address to its lowercase string
 * representation.
 *
 * This function takes an Ethereum public key in binary format, converts it to a
 * lowercase hexadecimal string, and stores the result in the provided `out`
 * buffer. The resulting string will be null-terminated.
 *
 * @param in A pointer to the binary Ethereum public key.
 * @param out A pointer to the buffer where the lowercase string representation
 * will be stored. The buffer must be at least 43 bytes long.
 * @param out_len The length of the output buffer `out`.
 * @param chainId The chain ID to be used (for future compatibility or other
 * uses).
 * @return true if the conversion was successful and the output buffer contains
 * the resulting string, false if the output buffer is too small or an error
 * occurs.
 *
 * @example
 * uint8_t*:0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB ->
 *      char*:"0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB\0"
 */
bool getEthDisplayableAddress(const uint8_t *in, char *out, size_t out_len, uint64_t chainId);

/**
 * @brief Converts an Ethereum hex address string to a TRON Base58Check address.
 *
 * Accepts both `0x`-prefixed and non-prefixed 40-hex-character Ethereum
 * address strings. The output buffer must be at least
 * `TRON_BASE58CHECK_ADDRESS_SIZE + 1` bytes long.
 *
 * @param ethAddress Ethereum address string (40 hex chars, with optional `0x`).
 * @param out58 Output buffer for the TRON Base58Check string.
 * @param out58_len Size of the output buffer.
 * @return true on success, false on invalid input or insufficient output size.
 */
bool ethToTronBase58(const char *ethAddress, char *out58, size_t out58_len);

/**
 * @brief Encodes a 20-byte (EVM-style) address as a TRON Base58Check string.
 *
 * Prepends the TRON mainnet prefix byte (0x41) and Base58Check-encodes the result,
 * producing a "T..." address. Used to display addresses that are held internally as
 * raw 20-byte values (GCS fields, trusted-name fallbacks) in TRON format.
 *
 * @param eth20 The 20-byte address.
 * @param out58 Output buffer for the TRON Base58Check string.
 * @param out58_len Size of the output buffer.
 * @return true on success, false on invalid input or insufficient output size.
 */
bool tronBase58FromBinary(const uint8_t *eth20, char *out58, size_t out58_len);

/**
 * @brief Decodes a TRON Base58Check address ("T...") into its 20-byte form.
 *
 * The inverse of \ref tronBase58FromBinary. Validates the fixed 34-character length,
 * the Base58Check checksum, and the TRON mainnet prefix byte (0x41), then outputs the
 * 20-byte (EVM-style) address. Note the underlying SDK base58_decode performs no
 * checksum verification; this function does.
 *
 * @param in The NUL-terminated TRON Base58Check address string.
 * @param out20 Output buffer for the 20-byte address.
 * @return true on success, false on invalid length, charset, checksum or prefix.
 */
bool tronBase58ToBinary(const char *in, uint8_t *out20);

/**
 * @brief Length-explicit variant of \ref tronBase58ToBinary.
 *
 * For callers holding the address as a (non-NUL-terminated) buffer slice, e.g. a CAL
 * descriptor field. Validates that \p len is exactly the TRON Base58Check length.
 *
 * @param in Pointer to the Base58Check characters (need not be NUL-terminated).
 * @param len Number of characters at \p in.
 * @param out20 Output buffer for the 20-byte address.
 * @return true on success, false on invalid length, charset, checksum or prefix.
 */
bool tronBase58ToBinaryLen(const char *in, size_t len, uint8_t *out20);

/**
 * @brief Decodes a 32-byte TVM ABI address word into its 20-byte form.
 *
 * Accepts both address encodings used by the TRON ecosystem:
 * - twelve zero bytes followed by the 20-byte address;
 * - eleven zero bytes followed by the 0x41 mainnet prefix and the 20-byte
 *   address, as emitted by java-tron's native ABI helpers.
 *
 * Any other non-zero high byte is rejected so normalization cannot change the
 * reviewed destination.
 *
 * @param word The complete 32-byte ABI word.
 * @param out20 Output buffer for the normalized 20-byte address.
 * @return true on success, false on an invalid high-byte encoding.
 */
bool tronAbiAddressToBinary(const uint8_t word[static INT256_LENGTH],
                            uint8_t out20[static ADDRESS_LENGTH]);

/**
 * @brief Checks if a buffer is entirely filled with zeroes.
 *
 * This function examines the first `n` bytes of the buffer pointed to by `buf`
 * to determine if all bytes are zero.
 *
 * @param buf A pointer to the buffer to be checked.
 * @param n The number of bytes to check in the buffer.
 * @return 1 if all bytes in the buffer are zero, 0 otherwise.
 */
int allzeroes(const void *buf, size_t n);

/**
 * @brief Checks if a buffer is entirely filled with the maximum byte value
 * (0xff).
 *
 * This function examines the first `n` bytes of the buffer pointed to by `buf`
 * to determine if all bytes are equal to 0xff.
 *
 * @param buf A pointer to the buffer to be checked.
 * @param n The number of bytes to check in the buffer.
 * @return 1 if all bytes in the buffer are 0xff, 0 otherwise.
 */
int ismaxint(const uint8_t *buf, int n);

// --8<-- [end:common_utils]
