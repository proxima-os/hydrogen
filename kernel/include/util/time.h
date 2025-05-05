#pragma once

#include "arch/time.h"
#include "kernel/time.h"
#include <stdint.h>

#define FS_PER_SEC 1000000000000000ull
#define NS_PER_SEC 1000000000ull

timeconv_t timeconv_create(uint64_t src_freq, uint64_t dst_freq);

void arch_queue_timer_irq(uint64_t deadline);
void time_handle_irq(void);
