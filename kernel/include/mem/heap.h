#pragma once

#include <stddef.h>

// size <= PAGE_SIZE, returned pointers are aligned to a power of two >= size, NULL on failure
void *kalloc(size_t size);

void *krealloc(void *ptr, size_t old_size, size_t size);

void kfree(void *ptr, size_t size);
