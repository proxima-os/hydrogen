#include "time/tsc.h"
#include "cpu/cpu.h"
#include "kernel/time.h"
#include "kernel/vdso.h"
#include "time/time.h"
#include "util/logging.h"
#include <stdint.h>

static timeconv_t ns2tsc_conv;

static uint64_t read_tsc(void) {
    return timeconv_apply(vdso_info.time.tsc, read_tsc_value());
}

static uint64_t ns_to_tsc(uint64_t value) {
    return timeconv_apply(ns2tsc_conv, value);
}

void init_tsc(uint64_t frequency) {
    if (!cpu_features.tsc_invariant) return;

    printk("time: tsc is available (%U.%6U MHz)\n", frequency / 1000000, frequency % 1000000);

    vdso_info.time.style = VDSO_TIME_TSC;
    vdso_info.time.tsc = create_timeconv(frequency, NS_PER_SEC);
    ns2tsc_conv = create_timeconv(NS_PER_SEC, frequency);

    if (timer_cleanup) timer_cleanup();

    read_time = read_tsc;
    read_time_unlocked = read_tsc;
    get_tsc_value = ns_to_tsc;
    timer_cleanup = NULL;
}
