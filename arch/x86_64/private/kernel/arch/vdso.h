#pragma once

#include "kernel/time.h"
#include "kernel/x86_64/kvmclock.h"
#include <stdbool.h>

typedef enum {
    X86_64_TIME_SYSCALL,
    X86_64_TIME_KVMCLOCK,
    X86_64_TIME_TSC,
} x86_64_time_source_t;

typedef struct {
    kvmclock_info_t kvmclock;
    timeconv_t tsc2ns_conv;
    x86_64_time_source_t time_source;
    bool fsgsbase : 1;
} arch_vdso_info_t;
