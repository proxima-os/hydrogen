#pragma once

#include "kernel/vdso.h"
#include <stdint.h>

extern uint64_t (*x86_64_read_time)(void);

static inline uint64_t arch_read_time(void) {
    return x86_64_read_time() - vdso_info.arch.time_offset;
}
