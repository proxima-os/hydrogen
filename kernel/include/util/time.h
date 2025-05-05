#pragma once

#include "arch/time.h"
#include "kernel/time.h"
#include <stdint.h>

#define FS_PER_SEC 1000000000000000ull
#define NS_PER_SEC 1000000000ull

timeconv_t timeconv_create(uint64_t src_freq, uint64_t dst_freq);

static inline void stall(uint64_t nanoseconds) {
    uint64_t start = arch_read_time();

    for (;;) {
        if (arch_read_time() - start >= nanoseconds) break;
    }
}
