#pragma once

#include <stdint.h>

static inline uint64_t x86_64_read_tsc(void) {
    uint32_t low;
    uint32_t high;
    asm volatile("lfence; rdtsc" : "=a"(low), "=d"(high)::"memory");
    return ((uint64_t)high << 32) | low;
}
