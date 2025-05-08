#pragma once

#include <stdint.h>

extern uint64_t (*x86_64_read_time)(void);
extern uint64_t x86_64_time_offset;

static inline uint64_t arch_read_time(void) {
    return x86_64_read_time() - x86_64_time_offset;
}
