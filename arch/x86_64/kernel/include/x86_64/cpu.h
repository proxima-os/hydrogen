#pragma once

#include "cpu/cpudata.h"
#include <stdbool.h>
#include <stdint.h>

#define X86_64_KERN_CS 0x08
#define X86_64_KERN_DS 0x10
#define X86_64_USER_DS 0x1b
#define X86_64_USER_CS 0x23
#define X86_64_SEL_TSS 0x28

typedef union {
    char text[12];
    struct {
        uint32_t ebx;
        uint32_t edx;
        uint32_t ecx;
    };
} x86_64_cpu_vendor_t;

static const x86_64_cpu_vendor_t x86_64_cpu_vendor_intel = {.text = "GenuineIntel"};

typedef struct {
    uint64_t paddr_mask;
    unsigned cpuid_low;
    unsigned cpuid_hyp;
    unsigned cpuid_high;
    x86_64_cpu_vendor_t cpu_vendor;
    x86_64_cpu_vendor_t hyp_vendor;
    bool x2apic : 1;
    bool tsc_deadline : 1;
    bool xsave : 1;
    bool hypervisor : 1;
    bool de : 1;
    bool mce : 1;
    bool apic : 1;
    bool pge : 1;
    bool mca : 1;
    bool pat : 1;
    bool fsgsbase : 1;
    bool smep : 1;
    bool smap : 1;
    bool umip : 1;
    bool nx : 1;
    bool huge_1gb : 1;
    bool la57 : 1;
    bool tsc_invariant : 1;
} x86_64_cpu_features_t;

extern x86_64_cpu_features_t x86_64_cpu_features;

void x86_64_cpu_detect(void);
void x86_64_cpu_init(cpu_t *self);
