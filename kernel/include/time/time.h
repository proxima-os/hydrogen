#pragma once

#include "kernel/time.h"
#include <stdint.h>

#define FS_PER_SEC 1000000000000000ul
#define NS_PER_SEC 1000000000ul

// These functions return the number of nanoseconds that have elapsed since some point in the past.
// `read_time_unlocked` must not take any locks while doing so, with the guarantee that neither versions of this
// function will be called while it is running.
extern uint64_t (*read_time)(void);
extern uint64_t (*read_time_unlocked)(void);

extern void (*timer_cleanup)(void);
extern uint64_t (*get_tsc_value)(uint64_t nanoseconds);

void init_time(void);

void use_short_calibration(void);

timeconv_t create_timeconv(uint64_t src_freq, uint64_t dst_freq);
