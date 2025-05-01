#pragma once

#include "cpu/cpudata.h"
#include <stddef.h>
#include <stdint.h>

typedef struct x86_64_cpu {
    uintptr_t syscall_entry_tmp; // must be the 1st field in the struct
    struct x86_64_cpu *self;
    cpu_t base;
} x86_64_cpu_t;

extern x86_64_cpu_t x86_64_boot_cpu;

#define x86_64_this_cpu_read(name)                                                         \
    ({                                                                                     \
        __typeof__(((x86_64_cpu_t *)0)->name) _val;                                        \
        asm volatile("mov %%gs:%c1, %0" : "=r"(_val) : "i"(offsetof(x86_64_cpu_t, name))); \
        _val;                                                                              \
    })
#define x86_64_this_cpu_write(name, value)                                               \
    ({                                                                                   \
        __typeof__(((x86_64_cpu_t *)0)->name) _val = (value);                            \
        asm volatile("mov %0, %%gs:%c1" ::"r"(_val), "i"(offsetof(x86_64_cpu_t, name))); \
    })
#define x86_64_get_current_cpu() x86_64_this_cpu_read(self)

#define boot_cpu (x86_64_boot_cpu.base)
#define this_cpu_read(name) x86_64_this_cpu_read(base.name)
#define this_cpu_write(name, value) x86_64_this_cpu_write(base.name, (value))
#define get_current_cpu() (&x86_64_get_current_cpu()->base)
