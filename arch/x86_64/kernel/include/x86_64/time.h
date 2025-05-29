#pragma once

#include "kernel/time.h"
#include <stdbool.h>
#include <stdint.h>

extern uint64_t (*x86_64_timer_get_tsc)(uint64_t time);
extern void (*x86_64_timer_cleanup)(void);
extern void (*x86_64_timer_confirm)(bool final);
extern timeconv_t x86_64_ns2lapic_conv;

void x86_64_switch_timer(
    uint64_t (*read)(void),
    uint64_t (*get_tsc)(uint64_t),
    void (*cleanup)(void),
    void (*confirm)(bool)
);

void x86_64_handle_timer(void);
