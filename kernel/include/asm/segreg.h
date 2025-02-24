#pragma once

#include <stdint.h>

static inline uint16_t read_ds(void) {
    uint16_t value;
    asm volatile("mov %%ds, %0" : "=r"(value));
    return value;
}

static inline uint16_t read_es(void) {
    uint16_t value;
    asm volatile("mov %%es, %0" : "=r"(value));
    return value;
}

static inline uint16_t read_fs(void) {
    uint16_t value;
    asm volatile("mov %%fs, %0" : "=r"(value));
    return value;
}

static inline uint16_t read_gs(void) {
    uint16_t value;
    asm volatile("mov %%gs, %0" : "=r"(value));
    return value;
}

static inline void write_ds(uint16_t value) {
    asm("mov %0, %%ds" ::"r"(value));
}

static inline void write_es(uint16_t value) {
    asm("mov %0, %%es" ::"r"(value));
}

static inline void write_fs(uint16_t value) {
    asm("mov %0, %%fs" ::"r"(value));
}

/// Writes gs, but clobbers IA32_KERNEL_GS_BASE instead of IA32_GS_BASE. Interrupts must be disabled.
static inline void write_gs_swapgs_wrapped(uint16_t value) {
    asm("swapgs; mov %0, %%gs; swapgs" ::"r"(value));
}
