#pragma once

#include <stddef.h>

#define X86_64_CR0_PE (1ul << 0)
#define X86_64_CR0_MP (1ul << 1)
#define X86_64_CR0_ET (1ul << 4)
#define X86_64_CR0_NE (1ul << 5)
#define X86_64_CR0_WP (1ul << 16)
#define X86_64_CR0_AM (1ul << 18)
#define X86_64_CR0_PG (1ul << 31)

#define X86_64_CR4_DE (1ul << 3)
#define X86_64_CR4_PAE (1ul << 5)
#define X86_64_CR4_MCE (1ul << 6)
#define X86_64_CR4_PGE (1ul << 7)
#define X86_64_CR4_OSFXSR (1ul << 9)
#define X86_64_CR4_OSXMMEXCEPT (1ul << 10)
#define X86_64_CR4_UMIP (1ul << 11)
#define X86_64_CR4_LA57 (1ul << 12)
#define X86_64_CR4_FSGSBASE (1ul << 16)
#define X86_64_CR4_OSXSAVE (1ul << 18)
#define X86_64_CR4_SMEP (1ul << 20)
#define X86_64_CR4_SMAP (1ul << 21)

static inline size_t x86_64_read_cr0(void) {
    size_t value;
    asm volatile("mov %%cr0, %0" : "=r"(value));
    return value;
}

static inline size_t x86_64_read_cr2(void) {
    size_t value;
    asm volatile("mov %%cr2, %0" : "=r"(value));
    return value;
}

static inline size_t x86_64_read_cr3(void) {
    size_t value;
    asm volatile("mov %%cr3, %0" : "=r"(value));
    return value;
}

static inline size_t x86_64_read_cr4(void) {
    size_t value;
    asm volatile("mov %%cr4, %0" : "=r"(value));
    return value;
}

static inline size_t x86_64_read_cr8(void) {
    size_t value;
    asm volatile("mov %%cr8, %0" : "=r"(value));
    return value;
}

static inline void x86_64_write_cr0(size_t value) {
    asm("mov %0, %%cr0" ::"r"(value));
}

static inline void x86_64_write_cr2(size_t value) {
    asm("mov %0, %%cr2" ::"r"(value));
}

static inline void x86_64_write_cr3(size_t value) {
    asm("mov %0, %%cr3" ::"r"(value));
}

static inline void x86_64_write_cr4(size_t value) {
    asm("mov %0, %%cr4" ::"r"(value));
}

static inline void x86_64_write_cr8(size_t value) {
    asm("mov %0, %%cr8" ::"r"(value));
}
