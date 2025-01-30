#pragma once

#ifndef NDEBUG
#include "compiler.h"
#endif

_Noreturn void panic(const char *format, ...);

#ifndef NDEBUG
#define ASSERT(x)                                                                                                      \
    do {                                                                                                               \
        if (unlikely(!(x))) panic("assertion `%s` failed in %s at %s:%d", #x, __func__, __FILE__, __LINE__);           \
    } while (0)
#else
#define ASSERT(x)                                                                                                      \
    do {                                                                                                               \
    } while (0)
#endif
