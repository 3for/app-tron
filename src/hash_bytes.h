#pragma once

#include <stdint.h>
#include "cx.h"

void hash_nbytes(const uint8_t *const bytes_ptr, size_t n, cx_hash_t *hash_ctx);
void hash_byte(uint8_t byte, cx_hash_t *hash_ctx);
bool hash_nbytes_no_throw(const uint8_t *bytes_ptr, size_t n, cx_hash_t *hash_ctx);
bool hash_byte_no_throw(uint8_t byte, cx_hash_t *hash_ctx);
// Finalize a hash context into out[0..out_len). Used by the generic_tx_parser
// (GCS) module; mirrors app-ethereum's hash_bytes.h.
bool finalize_hash(cx_hash_t *hash_ctx, uint8_t *out, size_t out_len);
