#pragma once

#include "gdt.h"
#include "mem/pmap.h"
#include "thread/sched.h"
#include "time/time.h"
#include "tss.h"
#include "util/spinlock.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
} cpuid_signature_t;

static const cpuid_signature_t HYPERVISOR_SIG_KVM = {
        0x4b4d564b,
        0x564b4d56,
        0x4d,
};

typedef struct {
    uint64_t paddr_mask;
    uint32_t max_std_leaf;
    uint32_t max_ext_leaf;
    struct {
        uint32_t max_leaf;
        cpuid_signature_t vendor;
    } hypervisor;
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
    struct cpu *next;
    uint32_t id;
    uint32_t apic_id;
    gdt_t gdt;
    struct cpu *pic_next;
    size_t irqs;
    timer_event_t *events;
    spinlock_t events_lock;
    sched_t sched;

    pmap_t *pmap;
    struct cpu *pmap_prev;
    struct cpu *pmap_next;
} cpu_t;

#define current_cpu (*(__seg_gs cpu_t *)0)
#define current_cpu_ptr (current_cpu.self)
#define current_thread (current_cpu.sched.current)

extern cpu_features_t cpu_features;
extern cpu_t *cpus;
extern size_t num_cpus;

void detect_cpu_features(void);

// assumes cpu->tss.ist is already filled
void init_cpu(cpu_t *cpu);
