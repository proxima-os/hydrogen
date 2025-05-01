#include "arch/cpudata.h"
#include "arch/stack.h"
#include "kernel/compiler.h"
#include "x86_64/cpu.h"
#include "x86_64/tss.h"
#include <stdint.h>

static unsigned char bsp_fatal_stack[KERNEL_STACK_SIZE];

USED void x86_64_prepare_main(void) {
    x86_64_cpu_detect();
    x86_64_boot_cpu.tss.ist[X86_64_IST_FATAL] = (uintptr_t)bsp_fatal_stack + sizeof(bsp_fatal_stack);
    x86_64_cpu_init(&x86_64_boot_cpu);
}
