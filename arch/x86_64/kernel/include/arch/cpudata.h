/* IWYU pragma: private, include "cpu/cpudata.h" */
#pragma once

#include "x86_64/tss.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uintptr_t syscall_entry_tmp; // must be the 1st field in the struct
    x86_64_tss_t tss;            // must be the 2nd field in the struct
    struct cpu *self;
    int current_pcid;
} arch_cpu_t;

#define __this_cpu_type(name) __typeof__(((cpu_t *)0)->name)
#define this_cpu_read(name)                                                         \
    ({                                                                              \
        __this_cpu_type(name) _val;                                                 \
        asm volatile("mov %%gs:%c1, %0" : "=r"(_val) : "i"(offsetof(cpu_t, name))); \
        _val;                                                                       \
    })
#define this_cpu_write(name, value)                                               \
    ({                                                                            \
        __this_cpu_type(name) _val = (value);                                     \
        asm volatile("mov %0, %%gs:%c1" ::"r"(_val), "i"(offsetof(cpu_t, name))); \
    })
#define this_cpu_read_tl(name) (*(__seg_gs __this_cpu_type(name) *)offsetof(cpu_t, name))
#define this_cpu_write_tl(name, value) (this_cpu_read_tl(name) = (value))
#define get_current_cpu() this_cpu_read(arch.self)
