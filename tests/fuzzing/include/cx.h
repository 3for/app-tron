#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CX_OK 0
#define CX_INTERNAL_ERROR 1
#define CX_LAST 1
#define CX_CURVE_256K1 1
#define CX_SHA256 2
#define CX_SHA512 3

#define CX_SHA256_SIZE 32
#define CX_KECCAK_256_SIZE 32

typedef int cx_err_t;
typedef int cx_curve_t;
typedef int cx_md_t;

typedef struct {
    uint8_t W[65];
    size_t W_len;
} cx_ecfp_public_key_t;

typedef struct {
    uint32_t seed;
    uint32_t mix;
    uint8_t out_len;
    size_t blen;
} cx_hash_t;

typedef cx_hash_t cx_sha3_t;
typedef cx_hash_t cx_sha256_t;

static inline cx_err_t cx_ecfp_init_public_key_no_throw(cx_curve_t curve,
                                                         const uint8_t *raw_key,
                                                         size_t raw_key_len,
                                                         cx_ecfp_public_key_t *key) {
    (void) curve;
    key->W_len = raw_key_len < sizeof(key->W) ? raw_key_len : sizeof(key->W);
    memcpy(key->W, raw_key, key->W_len);
    return CX_OK;
}

static inline int cx_ecdsa_verify_no_throw(const cx_ecfp_public_key_t *key,
                                           const uint8_t *hash,
                                           size_t hash_len,
                                           const uint8_t *signature,
                                           size_t signature_len) {
    (void) key;
    (void) hash;
    (void) hash_len;
    (void) signature;
    (void) signature_len;
    return 1;
}

#define CX_CHECK(call)            \
    do {                          \
        error = (call);           \
        if (error != CX_OK) {     \
            goto end;             \
        }                         \
    } while (0)

#define CX_ASSERT(call)           \
    do {                          \
        if ((call) != CX_OK) {    \
            __builtin_trap();     \
        }                         \
    } while (0)

static inline uint32_t cx_rotl32(uint32_t x, unsigned int r) {
    return (x << r) | (x >> (32U - r));
}

static inline void cx_hash_seed(cx_hash_t *ctx, uint32_t seed, uint8_t out_len) {
    ctx->seed = seed;
    ctx->mix = seed ^ 0x9E3779B9U;
    ctx->out_len = out_len;
    ctx->blen = 0U;
}

static inline cx_err_t cx_keccak_init_no_throw(cx_sha3_t *ctx, size_t bits) {
    cx_hash_seed(ctx, 0xC0DEC0DEU ^ (uint32_t) bits, (uint8_t) (bits / 8U));
    return CX_OK;
}

static inline cx_err_t cx_sha3_init_no_throw(cx_sha3_t *ctx, size_t bits) {
    cx_hash_seed(ctx, 0x53484133U ^ (uint32_t) bits, (uint8_t) (bits / 8U));
    return CX_OK;
}

static inline void cx_sha256_init(cx_sha256_t *ctx) {
    cx_hash_seed(ctx, 0x5A2565A2U, 32);
}

static inline void cx_sha224_init(cx_sha256_t *ctx) {
    cx_hash_seed(ctx, 0x5A2245A2U, 28);
}

static inline cx_err_t cx_hash_no_throw(cx_hash_t *ctx,
                                        uint32_t mode,
                                        const uint8_t *in,
                                        size_t in_len,
                                        uint8_t *out,
                                        size_t out_len) {
    for (size_t i = 0; i < in_len; i++) {
        ctx->mix ^= (uint32_t) in[i] + 0x9E3779B9U + (ctx->mix << 6) + (ctx->mix >> 2);
        ctx->mix = cx_rotl32(ctx->mix, 5U) ^ ctx->seed;
        ctx->seed += ctx->mix + (uint32_t) i;
    }
    ctx->blen += in_len;

    if ((mode & CX_LAST) != 0U) {
        const size_t produced = (out_len < ctx->out_len) ? out_len : ctx->out_len;

        for (size_t i = 0; i < produced; i++) {
            const uint32_t word = ctx->mix + (uint32_t) (i * 0x45D9F3BU) + ctx->seed;
            out[i] = (uint8_t) (word >> ((i & 3U) * 8U));
            ctx->mix = cx_rotl32(ctx->mix ^ word, 3U);
        }
    }

    return CX_OK;
}

static inline size_t cx_hash_sha256(const uint8_t *in,
                                    size_t in_len,
                                    uint8_t *out,
                                    size_t out_len) {
    cx_sha256_t ctx;

    cx_sha256_init(&ctx);
    return (cx_hash_no_throw((cx_hash_t *) &ctx, CX_LAST, in, in_len, out, out_len) == CX_OK)
               ? out_len
               : 0;
}

static inline cx_err_t cx_keccak_256_hash(const uint8_t *in,
                                          size_t in_len,
                                          uint8_t out[static CX_KECCAK_256_SIZE]) {
    cx_sha3_t ctx;

    cx_keccak_init_no_throw(&ctx, 256);
    return cx_hash_no_throw((cx_hash_t *) &ctx, CX_LAST, in, in_len, out, CX_KECCAK_256_SIZE);
}

static inline uint32_t cx_crc32_update(uint32_t crc, const void *buf, size_t len) {
    const uint8_t *bytes = (const uint8_t *) buf;

    crc = ~crc;
    for (size_t i = 0; i < len; i++) {
        crc ^= bytes[i];
        for (unsigned int bit = 0; bit < 8U; bit++) {
            const uint32_t mask = -(crc & 1U);
            crc = (crc >> 1U) ^ (0xEDB88320U & mask);
        }
    }
    return ~crc;
}

static inline cx_err_t cx_math_mult_no_throw(uint8_t *out,
                                             const uint8_t *a,
                                             const uint8_t *b,
                                             size_t len) {
    memset(out, 0, len * 2U);
    for (size_t i = 0; i < len; i++) {
        uint16_t carry = 0;
        const size_t ai = len - 1U - i;

        for (size_t j = 0; j < len; j++) {
            const size_t bi = len - 1U - j;
            const size_t oi = (len * 2U - 1U) - (i + j);
            const uint32_t prod =
                (uint32_t) a[ai] * (uint32_t) b[bi] + (uint32_t) out[oi] + carry;
            out[oi] = (uint8_t) (prod & 0xFFU);
            carry = (uint16_t) (prod >> 8);
        }

        size_t oi = len - 1U - i;
        while (carry != 0U) {
            const uint32_t sum = (uint32_t) out[oi] + carry;
            out[oi] = (uint8_t) (sum & 0xFFU);
            carry = (uint16_t) (sum >> 8);
            if (oi == 0U) {
                break;
            }
            oi--;
        }
    }
    return CX_OK;
}
