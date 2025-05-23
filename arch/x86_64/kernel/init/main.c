#include "init/main.h"
#include "arch/irq.h"
#include "arch/stack.h"
#include "cpu/cpudata.h"
#include "init/task.h"
#include "kernel/arch/vdso.h"
#include "kernel/compiler.h"
#include "kernel/vdso.h"
#include "util/slist.h"
#include "x86_64/cpu.h"
#include "x86_64/ioapic.h" /* IWYU pragma: keep */
#include "x86_64/lapic.h"  /* IWYU pragma: keep */
#include "x86_64/tss.h"
#include <stdint.h>

_Alignas(KERNEL_STACK_ALIGN) static unsigned char bsp_ist_stacks[X86_64_IST_MAX][KERNEL_STACK_SIZE];

USED void x86_64_prepare_main(void) {
    x86_64_cpu_detect();

    for (int i = 0; i < X86_64_IST_MAX; i++) {
        boot_cpu.arch.tss.ist[i] = (uintptr_t)bsp_ist_stacks[i] + sizeof(bsp_ist_stacks[i]);
    }

    slist_insert_tail(&cpus, &boot_cpu.node);
    x86_64_cpu_init(&boot_cpu);
}

static void init_arch_vdso_info(void) {
    vdso_info.arch.time_source = X86_64_TIME_SYSCALL;
    vdso_info.arch.fsgsbase = x86_64_cpu_features.fsgsbase;
}

INIT_DEFINE_EARLY(x86_64_vdso_info, init_arch_vdso_info);
INIT_DEFINE_EARLY(enable_interrupts, enable_irq, INIT_REFERENCE(x86_64_lapic), INIT_REFERENCE(x86_64_ioapic));
INIT_DEFINE_EARLY_AP(x86_64_interrupts_ap, enable_irq);
