/* IWYU pragma: private, include "proc/sched.h" */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t rsp;
    void *xsave;
    uint16_t ds, es, fs, gs;
    uintptr_t fs_base, gs_base;
    size_t orig_rax, orig_rdx;
    bool restarted;
    bool io_access;
} arch_thread_t;
