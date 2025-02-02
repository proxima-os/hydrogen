#pragma once

#include <stdint.h>

static inline uint64_t read_xcr(uint32_t idx) {
    uint32_t low, high;
    asm volatile("xgetbv" : "=a"(low), "=d"(high) : "c"(idx));
    return ((uint64_t)high << 32) | low;
}

static inline void write_xcr(uint32_t idx, uint64_t value) {
    uint32_t low = value;
    uint32_t high = value >> 32;
    asm("xsetbv" ::"a"(low), "d"(high), "c"(idx));
}
