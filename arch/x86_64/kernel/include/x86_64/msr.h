#pragma once

#include <stdint.h>

#define X86_64_MSR_APIC_BASE 0x1b
#define X86_64_MSR_APIC_BASE_EXTD (1ull << 10)
#define X86_64_MSR_APIC_BASE_ENABLE (1ull << 11)

#define X86_64_MSR_MCG_CAP 0x179
#define X86_64_MSR_MSG_CAP_COUNT 0xff
#define X86_64_MSR_MCG_CAP_MCG_CTL_P (1ull << 8)
#define X86_64_MSR_MCG_CAP_MCG_LMCE_P (1ull << 27)

#define X86_64_MSR_MCG_CTL 0x17b

#define X86_64_MSR_MCi_CTL(i) (0x400 + (i) * 4)
#define X86_64_MSR_MCi_STATUS(i) (0x401 + (i) * 4)

#define X86_64_MSR_EFER 0xc0000080
#define X86_64_MSR_EFER_SCE (1ull << 0)
#define X86_64_MSR_EFER_LME (1ull << 8)
#define X86_64_MSR_EFER_NXE (1ull << 11)

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
