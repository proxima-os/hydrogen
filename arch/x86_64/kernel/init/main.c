#include "init/main.h"
#include "acpi/acpi.h"
#include "arch/irq.h"
#include "arch/stack.h"
#include "cpu/cpudata.h"
#include "kernel/arch/vdso.h"
#include "kernel/compiler.h"
#include "kernel/vdso.h"
#include "sections.h"
#include "util/slist.h"
#include "x86_64/cpu.h"
#include "x86_64/ioapic.h"
#include "x86_64/lapic.h"
#include "x86_64/smp.h"
#include "x86_64/syscall.h"
#include "x86_64/time.h"
#include "x86_64/tss.h"
#include "x86_64/xsave.h"
#include <stdint.h>

_Alignas(KERNEL_STACK_ALIGN) static unsigned char bsp_ist_stacks[X86_64_IST_MAX][KERNEL_STACK_SIZE];

INIT_TEXT USED void x86_64_prepare_main(void) {
    x86_64_cpu_detect();

    for (int i = 0; i < X86_64_IST_MAX; i++) {
        boot_cpu.arch.tss.ist[i] = (uintptr_t)bsp_ist_stacks[i] + sizeof(bsp_ist_stacks[i]);
    }

    slist_insert_tail(&cpus, &boot_cpu.node);
    x86_64_cpu_init(&boot_cpu);
}

INIT_TEXT static void init_arch_vdso_info(void) {
    vdso_info.arch.time_source = X86_64_TIME_SYSCALL;
    vdso_info.arch.fsgsbase = x86_64_cpu_features.fsgsbase;
}

INIT_TEXT void arch_init_early(void) {
    init_arch_vdso_info();
    x86_64_xsave_init();
    acpi_init();
    x86_64_lapic_init();
    x86_64_ioapic_init();
    enable_irq();
    x86_64_time_init();
    x86_64_syscall_init_local();
}

INIT_TEXT void arch_init_late(void) {
    x86_64_smp_init();
}

INIT_TEXT void arch_init_current(void *ctx) {
    x86_64_xsave_init_local();
    x86_64_lapic_init_local(ctx);
    enable_irq();
    x86_64_time_init_local();
    x86_64_syscall_init_local();
}
