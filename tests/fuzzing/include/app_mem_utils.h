#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define APP_MEM_ALLOC(size) malloc(size)
#define APP_MEM_CALLOC(buffer, size) \
    mem_utils_calloc((buffer), (size), false, __FILE__, __LINE__)
#define APP_MEM_FREE(ptr) free(ptr)
#define APP_MEM_FREE_AND_NULL(buffer) \
    mem_utils_free_and_null((buffer), __FILE__, __LINE__)
#define APP_MEM_STRDUP(str) \
    mem_utils_strdup((str), __FILE__, __LINE__)

static inline bool mem_utils_init(void *heap_start, size_t heap_size) {
    (void) heap_start;
    (void) heap_size;
    return true;
}

static inline void *mem_utils_alloc(size_t size, bool permanent, const char *file, int line) {
    (void) permanent;
    (void) file;
    (void) line;
    return malloc(size);
}

static inline bool mem_utils_calloc(void **buffer,
                                    size_t size,
                                    bool permanent,
                                    const char *file,
                                    int line) {
    (void) permanent;
    (void) file;
    (void) line;
    if (buffer == NULL) {
        return false;
    }
    // The real allocator does not free the previous *buffer value (callers clean
    // up explicitly before calloc), and *buffer is frequently uninitialised at
    // the call site, so freeing it here would crash. Just allocate.
    if (size == 0) {
        *buffer = NULL;
        return true;
    }
    *buffer = calloc(1, size);
    return *buffer != NULL;
}

static inline void mem_utils_free(void *ptr, const char *file, int line) {
    (void) file;
    (void) line;
    free(ptr);
}

static inline void mem_utils_free_and_null(void **buffer, const char *file, int line) {
    (void) file;
    (void) line;
    if ((buffer != NULL) && (*buffer != NULL)) {
        free(*buffer);
        *buffer = NULL;
    }
}

static inline char *mem_utils_strdup(const char *str, const char *file, int line) {
    size_t len;
    char *copy;

    (void) file;
    (void) line;
    if (str == NULL) {
        return NULL;
    }
    len = strlen(str) + 1U;
    copy = malloc(len);
    if (copy != NULL) {
        memcpy(copy, str, len);
    }
    return copy;
}
