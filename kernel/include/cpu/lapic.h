#pragma once

#include "cpu/cpu.h"

typedef enum {
    LAPIC_TIMER_ONESHOT = 0,
    LAPIC_TIMER_TSC_DEADLINE = 2,
} lapic_timer_mode_t;

void init_lapic_bsp(void);
void init_lapic(void);

void lapic_arm_timer(lapic_timer_mode_t mode, bool interrupts);
void lapic_start_timer(uint32_t ticks);
uint32_t lapic_read_timer(void);

void send_ipi(int vector, cpu_t *dest);
