#pragma once

#include <stddef.h>

/// Returns a block of memory that is power-of-two aligned to >=size. Does not work on object >PAGE_SIZE.
void *kmalloc(size_t size);
void *krealloc(void *ptr, size_t old_size, size_t new_size);
void kfree(void *ptr, size_t size);
