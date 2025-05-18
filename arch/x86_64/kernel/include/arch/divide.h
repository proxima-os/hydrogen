#pragma once

#include <stdint.h>

static inline uint64_t x86_64_div(__uint128_t dividend, uint64_t *divisor) {
    uint64_t quot;
    asm("divq %3" : "=a"(quot), "=d"(*divisor) : "A"(dividend), "rm"(*divisor));
    return quot;
}

static inline uint64_t udiv128(__uint128_t *dividend, uint64_t divisor) {
    uint64_t high = *dividend >> 64;
    uint64_t low = *dividend;

    uint64_t high2 = divisor;
    high = x86_64_div(high, &high2);
    uint64_t rem = divisor;
    low = x86_64_div(((__uint128_t)high2 << 64) | low, &rem);

    *dividend = ((__uint128_t)high << 64) | low;
    return rem;
}
