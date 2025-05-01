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
