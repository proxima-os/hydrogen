#include "x86_64/tsc.h"
#include "arch/divide.h"
#include "arch/irq.h"
#include "arch/time.h"
#include "kernel/compiler.h"
#include "kernel/time.h"
#include "kernel/x86_64/tsc.h"
#include "util/printk.h"
#include "util/time.h"
#include "x86_64/cpu.h"
#include "x86_64/cpuid.h"
#include "x86_64/lapic.h"
#include "x86_64/time.h"
#include <stdint.h>

#define STABLE_READ_THRESHOLD 1000 /* read must not take more than 1us */
#define STABLE_READ_TRIES 10000

#define CALIBRATION_TIME_NS 500000000 /* 500ms */

static uint64_t tsc_freq;
static uint64_t lapic_freq;
static timeconv_t tsc2time_conv;
static timeconv_t time2tsc_conv;

typedef struct {
    uint64_t nanoseconds;
    uint64_t tsc;
    uint32_t lapic;
} timer_data_t;

static uint64_t ref_elapsed(uint64_t start, uint64_t end) {
    if (end < start) end += UINT32_MAX;
    ASSERT(start <= end);
    return end - start;
}

static bool read_time_stable(timer_data_t *data) {
    irq_state_t state = save_disable_irq();

    for (int i = 0; i < STABLE_READ_TRIES; i++) {
        data->nanoseconds = arch_read_time();
        data->tsc = x86_64_read_tsc();
        data->lapic = x86_64_lapic_timer_remaining();
        uint64_t end = arch_read_time();

        if (ref_elapsed(data->nanoseconds, end) <= STABLE_READ_THRESHOLD) {
            restore_irq(state);
            data->lapic = UINT32_MAX - data->lapic;
            return true;
        }
    }

    restore_irq(state);
    printk("tsc: failed to get a stable reading\n");
    return false;
}

static uint64_t get_freq(uint64_t ticks, uint64_t elapsed) {
    __uint128_t temp = (__uint128_t)NS_PER_SEC * ticks + (elapsed / 2);
    udiv128(&temp, elapsed);
    return temp;
}

static bool determine_frequency(void) {
    if (x86_64_cpu_features.cpuid_low >= 0x15) {
        unsigned eax, ebx, ecx, edx;
        cpuid(0x15, &eax, &ebx, &ecx, &edx);

        if (ecx != 0) {
            lapic_freq = ecx;

            if (ebx != 0) {
                tsc_freq = ((lapic_freq * ebx) + (eax / 2)) / eax;
            }
        }
    }

    if (x86_64_cpu_features.hypervisor && x86_64_cpu_features.cpuid_hyp >= 0x40000010) {
        unsigned eax, ebx, ecx, edx;
        cpuid(0x40000010, &eax, &ebx, &ecx, &edx);

        if (eax != 0) {
            tsc_freq = (uint64_t)eax * 1000;
        }

        if (ebx != 0) {
            lapic_freq = (uint64_t)ebx * 1000;
        }
    }

    bool tsc_required = x86_64_cpu_features.tsc_invariant && tsc_freq == 0;
    bool lapic_required = !x86_64_cpu_features.tsc_deadline && lapic_freq == 0;

    if (!tsc_required && !lapic_required) return true;

    uint64_t calibration_time = CALIBRATION_TIME_NS;
    if (!tsc_required) calibration_time /= 10;

    if (x86_64_timer_confirm) x86_64_timer_confirm(false);

    if (lapic_required) {
        x86_64_lapic_timer_setup(X86_64_LAPIC_TIMER_ONESHOT, false);
        x86_64_lapic_timer_start(UINT32_MAX);
    }

    timer_data_t start, end;
    read_time_stable(&start);

    for (;;) {
        if (ref_elapsed(start.nanoseconds, arch_read_time()) >= calibration_time) {
            break;
        }
    }

    read_time_stable(&end);

    uint64_t elapsed = ref_elapsed(start.nanoseconds, end.nanoseconds);

    if (tsc_required) {
        tsc_freq = get_freq(end.tsc - start.tsc, elapsed);
    }

    if (lapic_required) {
        ENSURE(end.lapic < UINT32_MAX);
        lapic_freq = get_freq(end.lapic - start.lapic, elapsed);
        x86_64_lapic_timer_stop();
    }

    return true;
}

static uint64_t tsc_read_time(void) {
    return timeconv_apply(tsc2time_conv, x86_64_read_tsc());
}

static uint64_t time_to_tsc(uint64_t time) {
    uint64_t tsc = timeconv_apply(time2tsc_conv, time);
    return tsc ? tsc : 1;
}

void x86_64_tsc_init(void) {
    if (!x86_64_cpu_features.tsc_invariant) x86_64_cpu_features.tsc_deadline = false;

    // do this even if tsc isn't invariant, since it determins lapic frequency too
    if (!determine_frequency()) return;

    if (lapic_freq != 0) {
        printk("lapic: %U.%6U MHz\n", lapic_freq / 1000000, lapic_freq % 1000000);
        x86_64_ns2lapic_conv = timeconv_create(NS_PER_SEC, lapic_freq);
    }

    if (!x86_64_cpu_features.tsc_invariant) {
        printk("tsc: not invariant\n");
        return;
    }

    printk("tsc: %U.%6U MHz\n", tsc_freq / 1000000, tsc_freq % 1000000);

    tsc2time_conv = timeconv_create(tsc_freq, NS_PER_SEC);
    time2tsc_conv = timeconv_create(NS_PER_SEC, tsc_freq);

    x86_64_switch_timer(tsc_read_time, time_to_tsc, NULL, NULL);
}
