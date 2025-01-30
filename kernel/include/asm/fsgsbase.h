#pragma once

#include <stdint.h>

static inline uintptr_t rdfsbase(void) {
    uintptr_t value;
    asm volatile("rdfsbase %0" : "=r"(value));
    return value;
}

static inline void wrfsbase(uintptr_t value) {
    asm("wrfsbase %0" ::"r"(value));
}
