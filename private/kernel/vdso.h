#pragma once

#include "kernel/arch/vdso.h"
#include "kernel/types.h"

extern struct {
    arch_vdso_info_t arch;
    timestamp_t boot_timestamp;
} vdso_info;

static inline int64_t real_time_from_boot_time(uint64_t boot_time) {
    return __atomic_load_n(&vdso_info.boot_timestamp, __ATOMIC_ACQUIRE) + boot_time;
}
