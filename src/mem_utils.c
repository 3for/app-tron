#include <stdint.h>
#include <stdio.h>
#include "app_mem_utils.h"
#include "mem_utils.h"

#define SIZE_MEM_BUFFER (1024 * 16)

static uint8_t mem_buffer[SIZE_MEM_BUFFER] __attribute__((aligned(sizeof(intmax_t))));

/**
 * Initialize the memory buffer.
 *
 * @return true if the initialization succeeded, false otherwise
 */
bool app_mem_init(void) {
    return mem_utils_init(mem_buffer, sizeof(mem_buffer));
}

/**
 * Format an unsigned number up to 32-bit into memory into an ASCII string.
 *
 * @param[in] value Value to write in memory
 * @return pointer to memory area or \ref NULL if the allocation failed
 */
char *mem_alloc_and_format_uint(uint32_t value) {
    char *mem_ptr;
    uint32_t value_copy;
    uint8_t size;

    size = 1;  // minimum size, even if 0
    value_copy = value;
    while (value_copy >= 10) {
        value_copy /= 10;
        size += 1;
    }
    // +1 for the null character
    if ((mem_ptr = APP_MEM_ALLOC(sizeof(char) * (size + 1)))) {
        snprintf(mem_ptr, (size + 1), "%u", value);
    }
    return mem_ptr;
}
