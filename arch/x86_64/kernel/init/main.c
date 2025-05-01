#include "arch/cpudata.h"
#include "kernel/compiler.h"
#include "x86_64/cpu.h"

USED void x86_64_prepare_main(void) {
    x86_64_cpu_init(&x86_64_boot_cpu);
}
