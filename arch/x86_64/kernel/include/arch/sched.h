/* IWYU pragma: private, include "proc/sched.h" */
#pragma once

#include <stddef.h>

typedef struct {
    size_t rsp;
    void *xsave;
} arch_thread_t;
