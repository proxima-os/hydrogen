#pragma once

#include <stddef.h>

#define memcmp __builtin_memcmp
#define memcpy __builtin_memcpy
#define memmove __builtin_memmove
#define memset __builtin_memset
#define strchr __builtin_strchr
#define strcmp __builtin_strcmp
#define strlen __builtin_strlen

size_t strnlen(const char *s, size_t n);
