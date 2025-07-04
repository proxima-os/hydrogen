/* IWYU pragma: private, include "cpu/cpudata.h" */
#pragma once

#include "x86_64/tss.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uintptr_t syscall_entry_tmp; // must be the 1st field in the struct
    x86_64_tss_t tss;            // must be the 2nd field in the struct
    struct cpu *self;
    uint64_t deadline;
    int current_pcid;
    uint32_t acpi_id;
    uint32_t apic_id;
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

#define this_cpu_inc32(name) ({ asm("addl $1, %%gs:%c0" ::"i"(offsetof(cpu_t, name)) : "cc"); })
#define this_cpu_dec32(name)                                                             \
    ({                                                                                   \
        bool _zero;                                                                      \
        asm volatile("subl $1, %%gs:%c1" : "=@ccz"(_zero) : "i"(offsetof(cpu_t, name))); \
        _zero;                                                                           \
    })
