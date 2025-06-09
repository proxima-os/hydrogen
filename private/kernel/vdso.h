#pragma once

#include "kernel/arch/vdso.h"
#include <stdint.h>

extern struct {
    arch_vdso_info_t arch;
    uint64_t boot_timestamp_low;
    uint64_t boot_timestamp_high;
    size_t boot_timestamp_seq;
} vdso_info;

static inline __int128_t real_time_from_boot_time(uint64_t boot_time) {
    for (;;) {
        size_t seq = __atomic_load_n(&vdso_info.boot_timestamp_seq, __ATOMIC_ACQUIRE);
        if (seq & 1) continue;

        uint64_t low = __atomic_load_n(&vdso_info.boot_timestamp_low, __ATOMIC_RELAXED);
        uint64_t high = __atomic_load_n(&vdso_info.boot_timestamp_high, __ATOMIC_RELAXED);

        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&vdso_info.boot_timestamp_seq, __ATOMIC_RELAXED) != seq) continue;

        return ((__uint128_t)high << 64) | low;
    }
}
