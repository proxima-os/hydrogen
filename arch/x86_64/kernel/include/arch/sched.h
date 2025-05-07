/* IWYU pragma: private, include "proc/sched.h" */
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t rsp;
    void *xsave;
    uint16_t ds, es, fs, gs;
    uintptr_t fs_base, gs_base;
} arch_thread_t;
