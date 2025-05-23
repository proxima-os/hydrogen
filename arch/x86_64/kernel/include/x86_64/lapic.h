#pragma once

#include "init/task.h"
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    X86_64_LAPIC_TIMER_ONESHOT = 0 << 17,
    X86_64_LAPIC_TIMER_PERIODIC = 1 << 17,
    X86_64_LAPIC_TIMER_TSC_DEADLINE = 2 << 17,
} x86_64_lapic_timer_mode_t;

struct acpi_madt;

INIT_DECLARE(x86_64_lapic);

void x86_64_lapic_init_local(struct acpi_madt *madt);
void x86_64_lapic_eoi(void);

#define X86_64_LAPIC_IPI_INIT (5u << 8)
#define X86_64_LAPIC_IPI_INIT_DEASSERT ((1u << 15) | (5u << 8))
#define X86_64_LAPIC_IPI_STARTUP (6u << 8)

void x86_64_lapic_ipi(uint32_t target_id, uint8_t vector, uint32_t flags);

void x86_64_lapic_timer_setup(x86_64_lapic_timer_mode_t mode, bool interrupt);
void x86_64_lapic_timer_start(uint32_t count);
uint32_t x86_64_lapic_timer_remaining(void);

void x86_64_lapic_irq_error(void);
void x86_64_lapic_irq_spurious(void);

void x86_64_lapic_irq_handle(uint8_t vector);

static inline void x86_64_lapic_timer_stop(void) {
    x86_64_lapic_timer_start(0);
}
