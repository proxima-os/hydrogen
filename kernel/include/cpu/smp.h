#pragma once

#include <stddef.h>

struct cpu;

typedef enum {
    SMP_REMOTE_NOOP,
    SMP_REMOTE_HALT,
    SMP_REMOTE_PREEMPT,
    SMP_REMOTE_TLB,
    SMP_REMOTE_LEAVE_PMAP,
} smp_remote_call_type_t;

void smp_call_remote(struct cpu *dest, smp_remote_call_type_t type);
