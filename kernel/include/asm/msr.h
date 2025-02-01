#pragma once

#include <stdint.h>

#define MSR_KVM_SYSTEM_TIME 0x12
#define MSR_KVM_SYSTEM_TIME_NEW 0x4b564d01

#define MSR_APIC_BASE 0x1b
#define MSR_APIC_BASE_EXTD 0x400

#define MSR_GS_BASE 0xc0000101

static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t low, high;
    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

static inline void wrmsr(uint32_t msr, uint64_t value) {
    uint32_t low = value;
    uint32_t high = value >> 32;
    asm("wrmsr" ::"a"(low), "d"(high), "c"(msr));
}
