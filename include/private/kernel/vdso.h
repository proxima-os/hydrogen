#pragma once

#include "kernel/kvmclock.h"
#include "kernel/time.h"

typedef enum {
    VDSO_TIME_SYSCALL,
    VDSO_TIME_KVMCLOCK,
    VDSO_TIME_TSC,
} vdso_time_style_t;

typedef struct {
    struct {
        vdso_time_style_t style;
        kvmclock_info_t kvmclock;
        timeconv_t tsc;
    } time;
} vdso_info_t;

extern vdso_info_t vdso_info;
