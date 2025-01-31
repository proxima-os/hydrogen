#pragma once

#include <stddef.h>

int memcmp(const void *s1, const void *s2, size_t n);
void *memcpy(void *restrict dest, const void *restrict src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memset(void *dest, int value, size_t n);
