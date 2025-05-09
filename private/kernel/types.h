#pragma once

#include <stdint.h>

#if SIZE_MAX == UINT32_MAX
typedef int32_t ssize_t;
#define SSIZE_MIN INT32_MIN
#define SSIZE_MAX INT32_MAX
#elif SIZE_MAX == UINT64_MAX
typedef int64_t ssize_t;
#define SSIZE_MIN INT64_MIN
#define SSIZE_MAX INT64_MAX
#else
#error "Unsupported size_t width"
#endif

typedef int64_t timestamp_t; // posix time in nanoseconds
