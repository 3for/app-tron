#include "hash_bytes.h"

/**
 * Continue given progressive hash on given bytes
 *
 * @param[in] bytes_ptr pointer to bytes
 * @param[in] n number of bytes to hash
 * @param[in] hash_ctx pointer to the hashing context
 */
void hash_nbytes(const uint8_t *bytes_ptr, size_t n, cx_hash_t *hash_ctx) {
    CX_ASSERT(cx_hash_no_throw(hash_ctx, 0, bytes_ptr, n, NULL, 0));
}

/**
 * Continue given progressive hash on given byte
 *
 * @param[in] byte byte to hash
 * @param[in] hash_ctx pointer to the hashing context
 */
void hash_byte(uint8_t byte, cx_hash_t *hash_ctx) {
    hash_nbytes(&byte, 1, hash_ctx);
}

bool hash_nbytes_no_throw(const uint8_t *bytes_ptr, size_t n, cx_hash_t *hash_ctx) {
    return (hash_ctx != NULL) && ((bytes_ptr != NULL) || (n == 0U)) &&
           (cx_hash_no_throw(hash_ctx, 0, bytes_ptr, n, NULL, 0) == CX_OK);
}

bool hash_byte_no_throw(uint8_t byte, cx_hash_t *hash_ctx) {
    return hash_nbytes_no_throw(&byte, 1U, hash_ctx);
}

/**
 * Finalize a progressive hash, writing the digest to out.
 * Mirrors app-ethereum's hash_bytes.c, used by the generic_tx_parser module.
 *
 * @param[in] hash_ctx pointer to the hashing context
 * @param[out] out output buffer for the digest
 * @param[in] out_len size of the output buffer
 * @return whether finalization succeeded
 */
bool finalize_hash(cx_hash_t *hash_ctx, uint8_t *out, size_t out_len) {
    if (cx_hash_no_throw(hash_ctx, CX_LAST, NULL, 0, out, out_len) != CX_OK) {
        PRINTF("Could not finalize struct hash!\n");
        return false;
    }
    return true;
}
