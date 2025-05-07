#pragma once

#define X86_64_MSR_KVM_SYSTEM_TIME 0x12

#define X86_64_MSR_APIC_BASE 0x1b
#define X86_64_MSR_APIC_BASE_EXTD (1ull << 10)
#define X86_64_MSR_APIC_BASE_ENABLE (1ull << 11)

#define X86_64_MSR_MTRR_CAP 0xfe

#define X86_64_MSR_MCG_CAP 0x179
#define X86_64_MSR_MSG_CAP_COUNT 0xff
#define X86_64_MSR_MCG_CAP_MCG_CTL_P (1ull << 8)
#define X86_64_MSR_MCG_CAP_MCG_LMCE_P (1ull << 27)

#define X86_64_MSR_MCG_CTL 0x17b

#define X86_64_MSR_MTRR_PHYS_BASE(n) (0x200 + (n) * 2)
#define X86_64_MSR_MTRR_PHYS_MASK(n) (0x201 + (n) * 2)

#define X86_64_MSR_MTRR_FIX_64K_00000 0x250

#define X86_64_MSR_MTRR_FIX_16K_80000 0x258
#define X86_64_MSR_MTRR_FIX_16K_A0000 0x259

#define X86_64_MSR_MTRR_FIX_4K_C0000 0x268
#define X86_64_MSR_MTRR_FIX_4K_C8000 0x269
#define X86_64_MSR_MTRR_FIX_4K_D0000 0x26a
#define X86_64_MSR_MTRR_FIX_4K_D8000 0x26b
#define X86_64_MSR_MTRR_FIX_4K_E0000 0x26c
#define X86_64_MSR_MTRR_FIX_4K_E8000 0x26d
#define X86_64_MSR_MTRR_FIX_4K_F0000 0x26e
#define X86_64_MSR_MTRR_FIX_4K_F8000 0x26f

#define X86_64_MSR_PAT 0x277

#define X86_64_MSR_MTRR_DEF_TYPE 0x2ff

#define X86_64_MSR_MCi_CTL(i) (0x400 + (i) * 4)
#define X86_64_MSR_MCi_STATUS(i) (0x401 + (i) * 4)

#define X86_64_MSR_TSC_DEADLINE 0x6e0

#define X86_64_MSR_KVM_SYSTEM_TIME_NEW 0x4b564d01

#define X86_64_MSR_EFER 0xc0000080
#define X86_64_MSR_EFER_SCE (1ull << 0)
#define X86_64_MSR_EFER_LME (1ull << 8)
#define X86_64_MSR_EFER_LMA (1ull << 10)
#define X86_64_MSR_EFER_NXE (1ull << 11)

#define X86_64_MSR_FS_BASE 0xc0000100
#define X86_64_MSR_GS_BASE 0xc0000101
#define X86_64_MSR_KERNEL_GS_BASE 0xc0000102

#ifndef __ASSEMBLER__

#include <stdint.h>

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

#endif
