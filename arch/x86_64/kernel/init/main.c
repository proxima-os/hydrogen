#include "arch/stack.h"
#include "cpu/cpudata.h"
#include "kernel/compiler.h"
#include "x86_64/cpu.h"
#include "x86_64/tss.h"
#include <stdint.h>

_Alignas(KERNEL_STACK_ALIGN) static unsigned char bsp_fatal_stack[KERNEL_STACK_SIZE];

USED void x86_64_prepare_main(void) {
    x86_64_cpu_detect();
    boot_cpu.arch.tss.ist[X86_64_IST_FATAL] = (uintptr_t)bsp_fatal_stack + sizeof(bsp_fatal_stack);
    x86_64_cpu_init(&boot_cpu);
}
