#pragma once

#include <stdint.h>

static inline void x86_64_write_xcr(uint32_t index, uint64_t value) {
    uint32_t low = value;
    uint32_t high = value >> 32;
    asm("xsetbv" ::"c"(index), "a"(low), "d"(high) : "memory");
}
