#pragma once

#include <stdint.h>

#define X86_64_MSR_GS_BASE 0xc0000101

static inline uint64_t x86_64_rdmsr(uint32_t msr) {
    uint32_t low, high;
    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr) : "memory");
    return ((uint64_t)high << 32) | low;
}

static inline void x86_64_wrmsr(uint32_t msr, uint64_t value) {
    uint32_t low = value;
    uint32_t high = value >> 32;
    asm("wrmsr" ::"a"(low), "d"(high), "c"(msr) : "memory");
}
