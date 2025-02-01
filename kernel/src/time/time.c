#include "time/time.h"
#include "asm/cpuid.h"
#include "cpu/cpu.h"
#include "time/hpet.h"
#include "time/kvmclock.h"
#include "time/tsc.h"
#include "util/panic.h"
#include <limits.h>
#include <stdint.h>

uint64_t (*read_time)(void);
uint64_t (*read_time_unlocked)(void);

uint64_t (*get_tsc_value)(uint64_t nanoseconds);

static uint64_t calibration_time_ns = 500000000ul; // 500ms by default

typedef struct {
    uint64_t nanoseconds;
    uint64_t tsc;
} calib_measurement_t;

__attribute__((noinline)) static void calib_measure(calib_measurement_t *out) {
    out->nanoseconds = read_time_unlocked();
    out->tsc = __builtin_ia32_rdtsc();
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

static uint64_t determine_cpu_frequencies(void) {
    if (cpu_features.max_std_leaf >= 0x15) {
        uint32_t eax, ebx, ecx, edx;
        cpuid(0x15, &eax, &ebx, &ecx, &edx);

        if (eax && ebx && ecx) {
            return ((uint64_t)ecx * ebx + (eax / 2)) / eax;
        }
    }

    // https://lwn.net/Articles/301888/
    if (cpu_features.hypervisor.max_leaf >= 0x40000010) {
        uint32_t eax, ebx, ecx, edx;
        cpuid(0x40000010, &eax, &ebx, &ecx, &edx);

        if (eax) {
            return (uint64_t)eax * 1000;
        }
    }

    // Need to calibrate
    if (!read_time_unlocked) panic("no calibration timer available");

    calib_measurement_t start, end;
    calib_measure(&start);

    do {
        calib_measure(&end);
    } while (calib_elapsed(&start, &end) < calibration_time_ns);

    uint64_t elapsed = end.nanoseconds - start.nanoseconds;
    return get_frequency(end.tsc - start.tsc, elapsed);
}

void init_time(void) {
    if (!cpu_features.tsc_invariant) use_short_calibration();

    // Initialize timers in order; the less desirable ones go first
    init_hpet();
    init_kvmclock();
    init_tsc(determine_cpu_frequencies());

    if (!read_time) panic("no supported time sources are available");
}

void use_short_calibration(void) {
    calibration_time_ns = 500000ul; // 500 microseconds
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
