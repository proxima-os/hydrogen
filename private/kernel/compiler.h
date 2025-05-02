#pragma once

#include <stddef.h>

#define UNUSED __attribute__((unused))
#define USED __attribute__((used))

#define likely(x) (__builtin_expect(!!(x), 1))
#define unlikely(x) (__builtin_expect(!!(x), 0))

#if !defined(__clang__) && __GNUC__ >= 15
#define NONSTRING __attribute__((nonstring))
#else
#define NONSTRING
#endif

extern _Noreturn void hydrogen_assert_fail(const char *expr, const char *func, const char *file, int line);

#define ENSURE(x) (likely(x) ? (void)0 : hydrogen_assert_fail(#x, __func__, __FILE__, __LINE__))

#ifndef NDEBUG
#define ASSERT(x) ENSURE(x)
#else
#define ASSERT(x) ((void)0)
#endif

#define CONCAT(x, y) x##y
#define EXPAND_CONCAT(x, y) CONCAT(x, y)

#define CONTAINER(type, name, value)                         \
    ({                                                       \
        void *_ptr = (value);                                \
        _ptr ? (type *)(_ptr - offsetof(type, name)) : NULL; \
    })

#ifndef NDEBUG
#define UNREACHABLE() ENSURE(!"unreachable")
#else
#define UNREACHABLE() __builtin_unreachable()
#endif
