#pragma once

#include "gdt.h"
#include "tss.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
} cpuid_signature_t;

typedef struct {
    uint64_t paddr_mask;
    cpuid_signature_t hypervisor;
    bool x2apic : 1;
    bool tsc_deadline : 1;
    bool xsave : 1;
    bool de : 1;
    bool tsc : 1;
    bool mce : 1;
    bool xapic : 1;
    bool global_pages : 1;
    bool mca : 1;
    bool pat : 1;
    bool fsgsbase : 1;
    bool smep : 1;
    bool smap : 1;
    bool umip : 1;
    bool nx : 1;
    bool huge_1gb : 1;
    bool tsc_invariant : 1;
} cpu_features_t;

typedef struct cpu {
    struct tss tss; // this needs to be the first thing in cpu_t, because its offset is used by ASM
    struct cpu *self;
    uint32_t id;
    gdt_t gdt;
} cpu_t;

#define current_cpu (*(__seg_gs cpu_t *)0)
#define current_cpu_ptr (current_cpu.self)

extern cpu_features_t cpu_features;

void detect_cpu_features(void);

// assumes cpu->tss.ist is already filled
void init_cpu(cpu_t *cpu);
