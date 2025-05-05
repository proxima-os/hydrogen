#pragma once

#include "cpu/cpudata.h"
#include "x86_64/idtvec.h"
#include "x86_64/lapic.h"

static inline void arch_remote_call(cpu_t *cpu) {
    x86_64_lapic_ipi(cpu->arch.apic_id, X86_64_IDT_IPI_REMOTE_CALL, 0);
}
