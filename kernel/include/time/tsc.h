#pragma once

#include <stdint.h>

// Returns the number of nanoseconds that have elapsed since boot
extern uint64_t (*read_time)(void);

void init_tsc(uint64_t frequency);
