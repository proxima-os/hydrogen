#pragma once

#include <stddef.h>

void *vmalloc(size_t size);
void vmfree(void *ptr, size_t size);
