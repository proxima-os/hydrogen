#pragma once

#define UNUSED __attribute__((unused))
#define USED __attribute__((used))

#define likely(x) (__builtin_expect(!!(x), 1))
#define unlikely(x) (__builtin_expect(!!(x), 0))

#if !defined(__clang__) && __GNUC__ >= 15
#define NONSTRING __attribute__((nonstring))
#else
#define NONSTRING
#endif

extern _Noreturn void __hydrogen_assert_fail(const char *expr, const char *func, const char *file, int line);

#ifndef NDEBUG
#define ASSERT(x) (likely(x) ? (void)0 : __hydrogen_assert_fail(#x, __func__, __FILE__, __LINE__))
#else
#define ASSERT(x) ((void)0)
#endif

#define CONCAT(x, y) x##y
#define EXPAND_CONCAT(x, y) CONCAT(x, y)
