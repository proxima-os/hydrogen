#pragma once

#include <stdint.h>

extern uint64_t hpet_period_fs;

void init_hpet(void);

uint64_t read_hpet(void);
