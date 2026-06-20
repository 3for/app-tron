#pragma once

#include <stddef.h>
#include <string.h>

// Several GCS headers (e.g. gtp_field.h) reference TLV_reception_t without
// including the TLV header directly; in the firmware build it arrives
// transitively. Force-include the lightweight TLV mock so it is always visible.
#include "tlv_library.h"

#ifndef PRINTF
#define PRINTF(...) ((void) 0)
#endif

// SDK helpers normally provided by os_helpers.h / ledger_assert.h. A failed
// LEDGER_ASSERT is a fatal invariant violation in firmware, so trap on it here
// to let the fuzzer surface inputs that break those invariants.
#ifndef ARRAYLEN
#define ARRAYLEN(array) (sizeof(array) / sizeof((array)[0]))
#endif
// IO flag set by signing handlers to defer the APDU reply (value matches the SDK).
#ifndef IO_ASYNCH_REPLY
#define IO_ASYNCH_REPLY (1 << 8)
#endif
#ifndef LEDGER_ASSERT
#define LEDGER_ASSERT(test, ...) \
    do {                         \
        if (!(test)) {           \
            __builtin_trap();    \
        }                        \
    } while (0)
#endif

static inline void fuzz_explicit_bzero(void *buf, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while (len-- > 0U) {
        *p++ = 0U;
    }
}

#define explicit_bzero(buf, len) fuzz_explicit_bzero((buf), (len))

#if !defined(__APPLE__)
enum { FUZZ_STRL_SOURCE_LIMIT = 4096 };

static inline size_t fuzz_bounded_src_len(const char *src) {
    return (src == NULL) ? 0U : strnlen(src, FUZZ_STRL_SOURCE_LIMIT);
}

static inline size_t fuzz_strlcpy(char *dst, const char *src, size_t dstsize) {
    size_t src_len = fuzz_bounded_src_len(src);

    if ((dst == NULL) || (src == NULL)) {
        return 0U;
    }

    if (dstsize != 0U) {
        size_t copy_len = (src_len >= dstsize) ? (dstsize - 1U) : src_len;
        memcpy(dst, src, copy_len);
        dst[copy_len] = '\0';
    }

    return src_len;
}

static inline size_t fuzz_strlcat(char *dst, const char *src, size_t dstsize) {
    size_t dst_len;
    size_t src_len;

    if ((dst == NULL) || (src == NULL)) {
        return 0U;
    }

    dst_len = strnlen(dst, dstsize);
    src_len = fuzz_bounded_src_len(src);

    if (dst_len == dstsize) {
        return dstsize + src_len;
    }

    if (dstsize != 0U) {
        size_t available = dstsize - dst_len - 1U;
        size_t copy_len = (src_len > available) ? available : src_len;
        memcpy(dst + dst_len, src, copy_len);
        dst[dst_len + copy_len] = '\0';
    }

    return dst_len + src_len;
}

#define strlcpy(dst, src, dstsize) fuzz_strlcpy((dst), (src), (dstsize))
#define strlcat(dst, src, dstsize) fuzz_strlcat((dst), (src), (dstsize))
#endif
