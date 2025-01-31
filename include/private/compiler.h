#pragma once

#define UNUSED __attribute__((unused))
#define USED __attribute__((used))

#define likely(x) (__builtin_expect(!!(x), 1))
#define unlikely(x) (__builtin_expect(!!(x), 0))

#ifndef NDEBUG
#define HYDROGEN_ASSERTIONS 1
#else
#define HYDROGEN_ASSERTIONS 0
#endif
