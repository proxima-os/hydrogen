#include "x86_64/tsc.h"
#include "arch/divide.h"
#include "arch/irq.h"
#include "arch/time.h"
#include "kernel/time.h"
#include "kernel/x86_64/tsc.h"
#include "util/printk.h"
#include "util/time.h"
#include "x86_64/cpu.h"
#include "x86_64/cpuid.h"
#include "x86_64/time.h"
#include <stdint.h>

#define STABLE_READ_THRESHOLD 1000 /* read must not take more than 1us */
#define STABLE_READ_TRIES 10000

#define CALIBRATION_TIME_NS 500000000 /* 500ms */

static uint64_t tsc_freq;
static timeconv_t tsc_conv;

typedef struct {
    uint64_t nanoseconds;
    uint64_t tsc;
} timer_data_t;

static bool read_time_stable(timer_data_t *data) {
    irq_state_t state = save_disable_irq();

    for (int i = 0; i < STABLE_READ_TRIES; i++) {
        data->nanoseconds = arch_read_time();
        data->tsc = x86_64_read_tsc();
        uint64_t end = arch_read_time();

        if (end - data->nanoseconds <= STABLE_READ_THRESHOLD) {
            restore_irq(state);
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

        if (ebx != 0 && ecx != 0) {
            tsc_freq = (uint64_t)ecx * ebx / eax;
            return true;
        }
    }

    if (x86_64_cpu_features.hypervisor && x86_64_cpu_features.cpuid_hyp >= 0x40000010) {
        unsigned eax, ebx, ecx, edx;
        cpuid(0x40000010, &eax, &ebx, &ecx, &edx);

        if (eax != 0) {
            tsc_freq = (uint64_t)eax * 1000;
            return true;
        }
    }

    if (x86_64_timer_confirm) x86_64_timer_confirm();

    timer_data_t start, end;
    read_time_stable(&start);
    stall(CALIBRATION_TIME_NS);
    read_time_stable(&end);

    uint64_t elapsed = end.nanoseconds - start.nanoseconds;
    tsc_freq = get_freq(end.tsc - start.tsc, elapsed);

    return true;
}

static uint64_t tsc_read_time(void) {
    return timeconv_apply(tsc_conv, x86_64_read_tsc());
}

void x86_64_tsc_init(void) {
    if (!x86_64_cpu_features.tsc_invariant) {
        printk("tsc: not invariant\n");
        return;
    }

    if (!determine_frequency()) return;
    printk("tsc: %U.%6U MHz\n", tsc_freq / 1000000, tsc_freq % 1000000);

    tsc_conv = timeconv_create(tsc_freq, NS_PER_SEC);
    x86_64_switch_timer(tsc_read_time, NULL, NULL);
}
