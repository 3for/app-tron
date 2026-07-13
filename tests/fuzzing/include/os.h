#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef PIC
#define PIC(x) (x)
#endif
#define UNUSED(x) ((void) (x))
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

static inline void nvm_write(void *dst, const void *src, size_t len) {
    memmove(dst, src, len);
}
