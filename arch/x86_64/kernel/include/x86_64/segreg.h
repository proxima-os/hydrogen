#pragma once

#include <stdint.h>

static inline uint16_t x86_64_read_ds(void) {
    uint16_t value;
    asm volatile("mov %%ds, %0" : "=rm"(value));
    return value;
}

static inline uint16_t x86_64_read_es(void) {
    uint16_t value;
    asm volatile("mov %%es, %0" : "=rm"(value));
    return value;
}

static inline uint16_t x86_64_read_fs(void) {
    uint16_t value;
    asm volatile("mov %%fs, %0" : "=rm"(value));
    return value;
}

static inline uint16_t x86_64_read_gs(void) {
    uint16_t value;
    asm volatile("mov %%gs, %0" : "=rm"(value));
    return value;
}

static inline void x86_64_write_ds(uint16_t value) {
    asm("mov %0, %%ds" ::"rm"(value));
}

static inline void x86_64_write_es(uint16_t value) {
    asm("mov %0, %%es" ::"rm"(value));
}

static inline void x86_64_write_fs(uint16_t value) {
    asm("mov %0, %%fs" ::"rm"(value));
}

// WARNING: This makes `get_current_cpu()` return 0! You must restore X86_64_MSR_GS_BASE.
static inline void x86_64_write_gs(uint16_t value) {
    asm("mov %0, %%gs" ::"rm"(value) : "memory");
}
