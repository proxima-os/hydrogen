#pragma once

#include "kernel/compiler.h"
#include "kernel/x86_64/tsc.h"
#include <stdint.h>

typedef struct {
    uint32_t version;
    uint32_t pad0;
    uint64_t tsc_timestamp;
    uint64_t system_time;
    uint32_t tsc_to_system_mul;
    int8_t tsc_shift;
    uint8_t flags;
    uint8_t pad[2];
} __attribute__((packed, aligned(8))) kvmclock_info_t;

static inline uint64_t x86_64_read_kvmclock(kvmclock_info_t *info) {
    uint32_t version = __atomic_load_n(&info->version, __ATOMIC_ACQUIRE);

    uint64_t tsc_value;
    uint64_t tsc_timestamp;
    uint64_t system_time;
    uint32_t mul;
    int8_t shift;

    for (;;) {
        if (likely((version & 1) == 0)) {
            tsc_timestamp = info->tsc_timestamp;
            system_time = info->system_time;
            mul = info->tsc_to_system_mul;
            shift = info->tsc_shift;
            tsc_value = x86_64_read_tsc(); // this performs an lfence
        }

        uint32_t new_version = __atomic_load_n(&info->version, __ATOMIC_ACQUIRE);
        if (likely((version & 1) == 0) && likely(new_version == version)) break;
        version = new_version;
    }

    uint64_t time = tsc_value - tsc_timestamp;

    if (shift >= 0) time <<= shift;
    else time >>= -shift;

    time = ((__uint128_t)time * mul) >> 32;
    time += system_time;
    return time;
}
