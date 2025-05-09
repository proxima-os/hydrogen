#include "util/time.h"
#include "arch/divide.h"
#include "arch/irq.h"
#include "arch/time.h"
#include "cpu/cpudata.h"
#include "kernel/compiler.h"
#include "kernel/vdso.h"
#include "limine.h"
#include "sections.h"
#include "util/list.h"
#include "util/spinlock.h"
#include <stdint.h>

INIT_TEXT void time_init(void) {
    static LIMINE_REQ struct limine_date_at_boot_request time_req = {.id = LIMINE_DATE_AT_BOOT_REQUEST};

    if (time_req.response) {
        set_current_timestamp((timestamp_t)time_req.response->timestamp * NS_PER_SEC);
    }
}

timestamp_t get_current_timestamp(void) {
    return real_time_from_boot_time(arch_read_time());
}

void set_current_timestamp(timestamp_t time) {
    __atomic_store_n(&vdso_info.boot_timestamp, time - arch_read_time(), __ATOMIC_RELEASE);
}

timeconv_t timeconv_create(uint64_t src_freq, uint64_t dst_freq) {
    /*
     * Time conversion is `T1 = (T1 * f1) / f0` (T0 = src value, f0 = src freq, T1 = dst value, f1 = dst freq).
     * However, that formula can overflow pretty quickly if the source frequency is high, making it unusable.
     * A workaround for this is using 128-bit integers for the intermediate value, but 128-bit division is either slow
     * or impossible depending on the platform. 128-bit multiplication is fine, though, and the equation can be
     * rearranged to not include 128-bit division:
     * 1. `T1 = (T1 * f1) / f0`
     * 2. `T1 = (T1 * f1 * 2^p) / (f0 * 2^p)`
     * 3. `T1 = (T1 * ((f1 * 2^p) / f0)) / 2^p`
     * Note that `((f1 * 2^p) / f0)` is a constant that can be calculated ahead of time, and the last division
     * is by a power of two and can thus be replaced with a right shift. This function calculates both `p` and
     * that constant.
     */

    // Find the highest value of `p` that doesn't make the multiplier overflow (`((f1 * 2^p) / f0) < 2^64`)

    // the highest value of `p` where the intermediate uint128_t can still be calculated
    unsigned max_p_intermediate = __builtin_clzl(dst_freq) + (128 - (sizeof(long) * 8));

    unsigned p;
    uint64_t multiplier;

    for (p = 0; p <= max_p_intermediate; p++) {
        __uint128_t cur_mult = (__uint128_t)dst_freq << p;
        udiv128(&cur_mult, src_freq);
        if (cur_mult > UINT64_MAX) break;
        multiplier = cur_mult;
    }

    p -= 1;

    return (timeconv_t){
            .multiplier = multiplier,
            .shift = p,
    };
}

void time_handle_irq(void) {
    list_t triggered = {};

    cpu_t *cpu = get_current_cpu();
    spin_acq_noirq(&cpu->events_lock);

    uint64_t time = arch_read_time();

    timer_event_t *event;

    for (;;) {
        event = LIST_HEAD(cpu->events, timer_event_t, node);
        if (!event || time < event->deadline) break;

        list_remove(&cpu->events, &event->node);
        list_insert_tail(&triggered, &event->node);
        __atomic_store_n(&event->cpu, NULL, __ATOMIC_RELEASE);
        __atomic_store_n(&event->running, true, __ATOMIC_RELEASE);
    }

    if (event != NULL) {
        arch_queue_timer_irq(event->deadline);
    }

    spin_rel_noirq(&cpu->events_lock);

    for (;;) {
        timer_event_t *event = LIST_REMOVE_HEAD(triggered, timer_event_t, node);
        if (!event) break;
        void (*func)(timer_event_t *) = event->func;
        __atomic_store_n(&event->running, false, __ATOMIC_RELEASE);
        func(event);
    }
}

void timer_queue_event(timer_event_t *event) {
    ASSERT(__atomic_load_n(&event->cpu, __ATOMIC_ACQUIRE) == NULL);
    ASSERT(event->deadline != 0);

    irq_state_t state = save_disable_irq();
    cpu_t *cpu = get_current_cpu();
    spin_acq_noirq(&cpu->events_lock);

    timer_event_t *next = LIST_HEAD(cpu->events, timer_event_t, node);
    while (next && next->deadline <= event->deadline) next = LIST_NEXT(*next, timer_event_t, node);

    list_insert_before(&cpu->events, &next->node, &event->node);
    __atomic_store_n(&event->cpu, cpu, __ATOMIC_RELEASE);

    if (event == LIST_HEAD(cpu->events, timer_event_t, node)) {
        arch_queue_timer_irq(event->deadline);
    }

    spin_rel_noirq(&cpu->events_lock);
    restore_irq(state);
}

static void ensure_not_running(timer_event_t *event) {
    for (;;) {
        if (!__atomic_load_n(&event->running, __ATOMIC_ACQUIRE)) return;
    }
}

void timer_cancel_event(timer_event_t *event) {
    cpu_t *cpu = __atomic_load_n(&event->cpu, __ATOMIC_ACQUIRE);

    if (cpu == NULL) {
        ensure_not_running(event);
        return;
    }

    irq_state_t state = spin_acq(&cpu->events_lock);

    for (;;) {
        cpu_t *ncpu = __atomic_load_n(&event->cpu, __ATOMIC_ACQUIRE);
        if (ncpu == cpu) break;

        spin_rel_noirq(&cpu->events_lock);
        cpu = ncpu;

        if (cpu == NULL) {
            ensure_not_running(event);
            return;
        }

        spin_acq_noirq(&cpu->events_lock);
    }

    list_remove(&cpu->events, &event->node);
    __atomic_store_n(&event->cpu, NULL, __ATOMIC_RELEASE);

    spin_rel(&cpu->events_lock, state);
    ensure_not_running(event);
}
