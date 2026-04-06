#pragma once

#include <stdlib.h>
#include <stdbool.h>

void mem_init(void);
void mem_reset(void);
void *mem_alloc(size_t size);
void mem_dealloc(size_t size);
void *mem_rev_alloc(size_t size);
void mem_rev_dealloc(size_t size);
bool mem_contains(const void *ptr, size_t size);
