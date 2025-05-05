#pragma once

#include <stdint.h>

extern void (*x86_64_timer_cleanup)(void);
extern void (*x86_64_timer_finalize)(void);

void x86_64_switch_timer(uint64_t (*read)(void), void (*cleanup)(void), void (*finalize)(void));
