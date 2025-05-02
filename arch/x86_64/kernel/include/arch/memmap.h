#pragma once

#include "x86_64/cpu.h"
#include <stdint.h>

static inline uint64_t cpu_max_phys_addr(void) {
    return x86_64_cpu_features.paddr_mask;
}

static inline unsigned cpu_vaddr_bits(void) {
    return x86_64_cpu_features.la57 ? 57 : 48;
}
