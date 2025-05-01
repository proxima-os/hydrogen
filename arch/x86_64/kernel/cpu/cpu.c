#include "x86_64/cpu.h"
#include "arch/cpudata.h"
#include "x86_64/msr.h"
#include <stdint.h>

x86_64_cpu_t x86_64_boot_cpu;

void x86_64_cpu_init(x86_64_cpu_t *self) {
    x86_64_wrmsr(X86_64_MSR_GS_BASE, (uintptr_t)self);
    self->self = self;
}
