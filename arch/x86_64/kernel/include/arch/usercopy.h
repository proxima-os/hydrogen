#pragma once

#include <stddef.h>

extern int (*user_memcpy)(void *dest, const void *src, size_t count);
extern int (*user_memset)(void *dest, int value, size_t count);
