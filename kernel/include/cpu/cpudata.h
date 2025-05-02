#pragma once

#include "arch/cpudata.h" /* IWYU pragma: export */
#include "proc/sched.h"
#include <stddef.h>

typedef struct cpu {
    arch_cpu_t arch; // must be the 1st field in the struct
    size_t id;
    sched_t sched;
} cpu_t;

extern cpu_t boot_cpu;

/* _tl-suffixed cpu-local macros are for data that is thread-local:
 * in other words, nothing gets messed up if the value is read/written
 * in more than one instruction and nothing gets messed up if the value
 * is cached by the compiler. */
#ifndef this_cpu_read_tl
#define this_cpu_read_tl this_cpu_read
#endif

#ifndef this_cpu_write_tl
#define this_cpu_write_tl this_cpu_write
#endif

#define current_thread this_cpu_read_tl(sched.current)
