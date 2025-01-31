#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t limit;
    void *base;
} __attribute__((packed)) table_desc_t;

static inline void load_gdt(void *base, size_t size) {
    table_desc_t desc = {size - 1, base};
    asm("lgdt %0" ::"m"(desc));
}

static inline void load_ldt(uint16_t selector) {
    asm("lldt %0" ::"r"(selector));
}

static inline void load_tss(uint16_t selector) {
    asm("ltr %0" ::"r"(selector));
}

static inline void load_idt(void *base, size_t size) {
    table_desc_t desc = {size - 1, base};
    asm("lidt %0" ::"m"(desc));
}
