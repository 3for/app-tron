#pragma once

#include <stddef.h>
#include <string.h>

#ifndef PRINTF
#define PRINTF(...) ((void) 0)
#endif

static inline void fuzz_explicit_bzero(void *buf, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while (len-- > 0U) {
        *p++ = 0U;
    }
}

#define explicit_bzero(buf, len) fuzz_explicit_bzero((buf), (len))

#if !defined(__APPLE__)
static inline size_t fuzz_strlcpy(char *dst, const char *src, size_t dstsize) {
    size_t src_len = strlen(src);

    if (dstsize != 0U) {
        size_t copy_len = (src_len >= dstsize) ? (dstsize - 1U) : src_len;
        memcpy(dst, src, copy_len);
        dst[copy_len] = '\0';
    }

    return src_len;
}

static inline size_t fuzz_strlcat(char *dst, const char *src, size_t dstsize) {
    size_t dst_len = strnlen(dst, dstsize);
    size_t src_len = strlen(src);

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
