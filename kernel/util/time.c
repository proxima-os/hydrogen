#include "util/time.h"
#include "arch/divide.h"
#include <stdint.h>

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
}
