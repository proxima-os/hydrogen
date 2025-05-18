#include "arch/time.h"
#include "cpu/cpudata.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/time.h"
#include "kernel/vdso.h"
#include "mem/memmap.h" /* IWYU pragma: keep */
#include "proc/sched.h"
#include "sections.h"
#include "util/panic.h"
#include "util/time.h"
#include "x86_64/cpu.h"
#include "x86_64/hpet.h"
#include "x86_64/init.h" /* IWYU pragma: keep */
#include "x86_64/kvmclock.h"
#include "x86_64/lapic.h"
#include "x86_64/msr.h"
#include "x86_64/time.h"
#include "x86_64/tsc.h"
#include <stdint.h>

static uint64_t no_time_read(void) {
    return 0;
}

static void no_time_confirm(bool final) {
    panic("no time source available");
}

uint64_t (*x86_64_read_time)(void) = no_time_read;
uint64_t (*x86_64_timer_get_tsc)(uint64_t);
void (*x86_64_timer_cleanup)(void);
void (*x86_64_timer_confirm)(bool) = no_time_confirm;
timeconv_t x86_64_ns2lapic_conv;

static void init_events(void) {
    if (x86_64_cpu_features.tsc_deadline) {
        ASSERT(x86_64_timer_get_tsc != NULL);
        x86_64_lapic_timer_setup(X86_64_LAPIC_TIMER_TSC_DEADLINE, true);
    } else {
        x86_64_lapic_timer_setup(X86_64_LAPIC_TIMER_ONESHOT, true);
    }
}

INIT_DEFINE_EARLY_AP(x86_64_time_ap, init_events, INIT_REFERENCE(x86_64_interrupts_ap));

static void init_timers(void) {
    x86_64_hpet_init();
    x86_64_kvmclock_init();
    x86_64_tsc_init();
    if (x86_64_timer_confirm) x86_64_timer_confirm(true);

    vdso_info.arch.time_offset = x86_64_read_time();
    init_events();
}

INIT_DEFINE_EARLY(arch_time, init_timers, INIT_REFERENCE(memory), INIT_REFERENCE(x86_64_interrupts));

void x86_64_switch_timer(
        uint64_t (*read)(void),
        uint64_t (*get_tsc)(uint64_t),
        void (*cleanup)(void),
        void (*confirm)(bool)
) {
    if (x86_64_timer_cleanup) x86_64_timer_cleanup();

    x86_64_read_time = read;
    x86_64_timer_get_tsc = get_tsc;
    x86_64_timer_cleanup = cleanup;
    x86_64_timer_confirm = confirm;
}

static void start_lapic_for_deadline(uint64_t cur, uint64_t deadline) {
    /* the +1 is to increase the chance the irq arrives late instead of early */
    uint64_t ticks = cur < deadline ? timeconv_apply(x86_64_ns2lapic_conv, deadline - cur) + 1 : 1;
    x86_64_lapic_timer_start(ticks <= UINT32_MAX ? ticks : UINT32_MAX);
}

void x86_64_handle_timer(void) {
    if (!x86_64_cpu_features.tsc_deadline) {
        uint64_t deadline = this_cpu_read(arch.deadline);
        uint64_t cur = arch_read_time();

        if (deadline > cur) {
            start_lapic_for_deadline(cur, deadline);
            x86_64_lapic_eoi();
            return;
        }
    }

    preempt_state_t state = preempt_lock();
    time_handle_irq();
    x86_64_lapic_eoi();
    preempt_unlock(state);
}

void arch_queue_timer_irq(uint64_t deadline) {
    if (deadline != 0) {
        if (x86_64_cpu_features.tsc_deadline) {
            x86_64_wrmsr(X86_64_MSR_TSC_DEADLINE, x86_64_timer_get_tsc(deadline + vdso_info.arch.time_offset));
        } else {
            this_cpu_write(arch.deadline, deadline);
            start_lapic_for_deadline(arch_read_time(), deadline);
        }
    } else if (x86_64_cpu_features.tsc_deadline) {
        x86_64_wrmsr(X86_64_MSR_TSC_DEADLINE, 0);
    } else {
        this_cpu_write(arch.deadline, 0);
        x86_64_lapic_timer_stop();
    }
}
