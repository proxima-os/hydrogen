#include "time/time.h"
#include "asm/cpuid.h"
#include "asm/irq.h"
#include "asm/msr.h"
#include "cpu/cpu.h"
#include "cpu/idt.h"
#include "cpu/irqvecs.h"
#include "cpu/lapic.h"
#include "kernel/time.h"
#include "thread/sched.h"
#include "time/hpet.h"
#include "time/kvmclock.h"
#include "time/tsc.h"
#include "util/panic.h"
#include "util/spinlock.h"
#include <limits.h>
#include <stdint.h>

uint64_t (*read_time)(void);
uint64_t (*read_time_unlocked)(void);

uint64_t (*get_tsc_value)(uint64_t nanoseconds);
void (*timer_cleanup)(void);

static uint64_t calibration_time_ns = 500000000ul; // 500ms by default
static timeconv_t ns2lapic_conv;

extern void fillfb(uint32_t color);

typedef struct {
    uint64_t nanoseconds;
    uint64_t tsc;
    uint32_t lapic;
} calib_measurement_t;

__attribute__((noinline)) static void calib_measure(calib_measurement_t *out) {
    out->nanoseconds = read_time_unlocked();
    out->tsc = read_tsc_value();
    out->lapic = UINT32_MAX - lapic_read_timer();
}

static uint64_t calib_elapsed(calib_measurement_t *t0, calib_measurement_t *t1) {
    return t1->nanoseconds - t0->nanoseconds;
}

static uint64_t div128(__uint128_t *dividend, uint64_t divisor) {
    uint64_t low = *dividend;
    uint64_t high = *dividend >> 64;
    uint64_t rem;

    asm("divq %[divisor]" : "=d"(rem), "=a"(high) : "0"(0ul), "1"(high), [divisor] "rm"(divisor));
    asm("divq %[divisor]" : "=d"(rem), "=a"(low) : "0"(rem), "1"(low), [divisor] "rm"(divisor));

    *dividend = low | ((__uint128_t)high << 64);
    return rem;
}

static uint64_t get_frequency(uint64_t ticks, uint64_t elapsed) {
    __uint128_t temp = (__uint128_t)NS_PER_SEC * ticks + (elapsed / 2);
    div128(&temp, elapsed);
    return temp;
}

static uint64_t determine_cpu_frequencies(uint64_t *lapic_out) {
    if (cpu_features.max_std_leaf >= 0x15) {
        uint32_t eax, ebx, ecx, edx;
        cpuid(0x15, &eax, &ebx, &ecx, &edx);

        if (eax && ebx && ecx) {
            *lapic_out = ecx;
            return ((uint64_t)ecx * ebx + (eax / 2)) / eax;
        }
    }

    // https://lwn.net/Articles/301888/
    if (cpu_features.hypervisor.max_leaf >= 0x40000010) {
        uint32_t eax, ebx, ecx, edx;
        cpuid(0x40000010, &eax, &ebx, &ecx, &edx);

        if (eax && ebx) {
            *lapic_out = (uint64_t)ebx * 1000;
            return (uint64_t)eax * 1000;
        }
    }

    // Need to calibrate
    if (!read_time_unlocked) panic("no calibration timer available");

    lapic_arm_timer(LAPIC_TIMER_ONESHOT, false);

    irq_state_t state = save_disable_irq();
    lapic_start_timer(UINT32_MAX);

    calib_measurement_t start, end;
    calib_measure(&start);

    do {
        calib_measure(&end);
    } while (calib_elapsed(&start, &end) < calibration_time_ns);

    restore_irq(state);

    uint64_t elapsed = end.nanoseconds - start.nanoseconds;
    *lapic_out = get_frequency(end.lapic - start.lapic, elapsed);
    return get_frequency(end.tsc - start.tsc, elapsed);
}

static void rearm_timer(timer_event_t *event) {
    if (event) {
        if (cpu_features.tsc_deadline) {
            wrmsr(MSR_TSC_DEADLINE, get_tsc_value(event->time));
        } else {
            uint64_t cur = read_time();
            uint64_t ticks = cur < event->time ? timeconv_apply(ns2lapic_conv, event->time - cur) + 1 : 1;
            if (ticks > UINT32_MAX) ticks = UINT32_MAX;
            lapic_start_timer(ticks);
        }
    }
}

static void handle_timer_irq(UNUSED idt_frame_t *frame, UNUSED void *ctx) {
    cpu_t *cpu = current_cpu_ptr;
    spin_lock_noirq(&cpu->events_lock);

    timer_event_t *first = NULL;
    timer_event_t *last = NULL;

    timer_event_t *cur = cpu->events;
    while (cur != NULL && cur->time < read_time()) {
        timer_event_t *next = cur->next;

        if (first) last->next = cur;
        else first = cur;
        last = cur;

        cur->queued = false;
        cur = next;
    }

    cpu->events = cur;
    rearm_timer(cur);

    if (first) {
        sched_disable_preempt();

        for (;;) {
            timer_event_t *next = first->next;
            first->handler(first);

            if (first != last) first = next;
            else break;
        }

        spin_unlock_noirq(&cpu->events_lock);
        lapic_eoi();
        sched_enable_preempt();
    } else {
        spin_unlock_noirq(&cpu->events_lock);
        lapic_eoi();
    }
}

void init_time(void) {
    if (!cpu_features.tsc_invariant) use_short_calibration();

    // Initialize timers in order; the less desirable ones go first
    init_hpet();
    init_kvmclock();

    uint64_t lapic_freq;
    init_tsc(determine_cpu_frequencies(&lapic_freq));
    ns2lapic_conv = create_timeconv(NS_PER_SEC, lapic_freq);

    if (!read_time) panic("no time sources are available");

    idt_install(VEC_IRQ_TIMER, handle_timer_irq, NULL);
}

void init_time_local(void) {
    if (cpu_features.tsc_deadline && get_tsc_value) {
        lapic_arm_timer(LAPIC_TIMER_TSC_DEADLINE, true);
    } else {
        cpu_features.tsc_deadline = false;
        lapic_arm_timer(LAPIC_TIMER_ONESHOT, true);
    }
}

void use_short_calibration(void) {
    calibration_time_ns /= 10;
}

timeconv_t create_timeconv(uint64_t src_freq, uint64_t dst_freq) {
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
    unsigned max_p_intermediate = __builtin_clzl(dst_freq) + (128 - (sizeof(unsigned long) * CHAR_BIT));

    unsigned p;
    uint64_t multiplier;

    for (p = 0; p <= max_p_intermediate; p++) {
        __uint128_t cur_mult = (__uint128_t)dst_freq << p;
        div128(&cur_mult, src_freq);
        if (cur_mult > UINT64_MAX) break;
        multiplier = cur_mult;
    }

    p -= 1;

    return (timeconv_t){
            .multiplier = multiplier,
            .shift = p,
    };
}

void event_init(timer_event_t *event, void (*handler)(struct timer_event *event)) {
    event->handler = handler;
    event->cpu = NULL;
    event->queued = false;
    spin_init(&event->lock);
}

void queue_event(timer_event_t *event) {
    cpu_t *cpu = current_cpu_ptr;

    irq_state_t state = spin_lock(&event->lock);

    ASSERT(!event->queued);
    event->cpu = cpu;
    event->queued = true;

    spin_lock_noirq(&cpu->events_lock);

    timer_event_t *prev = NULL;
    timer_event_t *next = cpu->events;

    while (next != NULL && next->time < event->time) {
        prev = next;
        next = next->next;
    }

    event->prev = prev;
    event->next = next;

    if (next) next->prev = event;

    if (prev) {
        prev->next = event;
    } else {
        cpu->events = event;
        rearm_timer(event);
    }

    spin_unlock_noirq(&cpu->events_lock);
    spin_unlock(&event->lock, state);
}

void cancel_event(timer_event_t *event) {
    irq_state_t state = spin_lock(&event->lock);

    if (event->cpu) {
        spin_lock_noirq(&event->cpu->events_lock);

        if (event->queued) {
            event->queued = false;

            if (event->prev) event->prev->next = event->next;
            else event->cpu->events = event->next;

            if (event->next) event->next->prev = event->prev;
        }

        spin_unlock_noirq(&event->cpu->events_lock);
    }

    spin_unlock(&event->lock, state);
}
