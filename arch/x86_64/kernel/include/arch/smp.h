#pragma once

#include "cpu/cpudata.h"
#include "cpu/smp.h"
#include "kernel/compiler.h"
#include "x86_64/idtvec.h"
#include "x86_64/lapic.h"

static inline void arch_remote_call(cpu_t *cpu, smp_remote_call_type_t type) {
    uint8_t vector;

    switch (type) {
    case SMP_REMOTE_NOOP: vector = X86_64_IDT_IPI_REMOTE_NOOP; break;
    case SMP_REMOTE_HALT: vector = X86_64_IDT_IPI_REMOTE_HALT; break;
    case SMP_REMOTE_PREEMPT: vector = X86_64_IDT_IPI_REMOTE_PREEMPT; break;
    case SMP_REMOTE_TLB: vector = X86_64_IDT_IPI_REMOTE_TLB; break;
    case SMP_REMOTE_LEAVE_PMAP: vector = X86_64_IDT_IPI_REMOTE_LEAVE_PMAP; break;
    default: UNREACHABLE();
    }

    x86_64_lapic_ipi(cpu->arch.apic_id, vector, 0);
}
