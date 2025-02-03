#pragma once

#include <stddef.h>

typedef struct magazine magazine_t;

typedef struct {
    magazine_t *cur;
    magazine_t *prev;
    int count;
    int prev_count;
} heap_cache_t;

// size <= PAGE_SIZE, returned pointers are aligned to a power of two >= size, NULL on failure
void *kalloc(size_t size);

void *krealloc(void *ptr, size_t old_size, size_t size);

void kfree(void *ptr, size_t size);
