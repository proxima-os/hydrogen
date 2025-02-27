#pragma once

#include <stdint.h>

typedef struct {
    uint64_t multiplier;
    unsigned shift;
} timeconv_t;

static inline uint64_t read_tsc_value(void) {
    uint32_t low, high;
    asm volatile("lfence; rdtsc" : "=a" (low), "=d" (high));
    return ((uint64_t)high << 32) | low;
}

static inline uint64_t timeconv_apply(timeconv_t conv, uint64_t value) {
    return ((__uint128_t)conv.multiplier * value) >> conv.shift;
}
