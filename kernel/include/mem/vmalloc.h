#pragma once

#include <stdbool.h>
#include <stddef.h>

void *vmalloc(size_t size);
void *vrealloc(void *ptr, size_t old_size, size_t new_size);
void vfree(void *ptr, size_t size);
