#pragma once

#include <stddef.h>
#include <stdint.h>

struct cpu;

typedef struct {
    uint64_t reserved;
    uint64_t kern_code;
    uint64_t kern_data;
    uint64_t user_data;
    uint64_t user_code;
    uint64_t tss_low;
    uint64_t tss_high;
} gdt_t;

#define SEL_KCODE (offsetof(gdt_t, kern_code))
#define SEL_KDATA (offsetof(gdt_t, kern_data))
#define SEL_UDATA (offsetof(gdt_t, user_data) | 3)
#define SEL_UCODE (offsetof(gdt_t, user_code) | 3)
#define SEL_TSS (offsetof(gdt_t, tss_low))

void init_gdt(struct cpu *cpu);
