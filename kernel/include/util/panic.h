#pragma once

#include "compiler.h"

_Noreturn void panic(const char *format, ...);

#if HYDROGEN_ASSERTIONS
#define ASSERT(x)                                                                                                      \
    do {                                                                                                               \
        if (unlikely(!(x))) panic("assertion failed: `%s` in %s at %s:%d", #x, __func__, __FILE__, __LINE__);          \
    } while (0)
#else
#define ASSERT(x)                                                                                                      \
    do {                                                                                                               \
    } while (0)
#endif
