#pragma once

#include "proc/event.h"

// called during early initialization, i.e. right before the init thread is started
void arch_init_early(void);

// called in the init thread after loader memory is reclaimed
void arch_init_late(void);

// the equivalent of arch_init_early for cpus other than the boot cpu
void arch_init_current(void *ctx);

_Noreturn void smp_init_current(event_t *event, void *ctx);
