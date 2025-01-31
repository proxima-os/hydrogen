#pragma once

#include <stdint.h>

static inline void invlpg(uintptr_t addr) {
    asm("invlpg (%0)" ::"r"(addr));
}
