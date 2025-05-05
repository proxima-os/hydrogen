#pragma once

#include <stdbool.h>
#include <stdint.h>

extern void (*x86_64_timer_cleanup)(void);
extern void (*x86_64_timer_confirm)(bool final);

void x86_64_switch_timer(uint64_t (*read)(void), void (*cleanup)(void), void (*confirm)(bool));
