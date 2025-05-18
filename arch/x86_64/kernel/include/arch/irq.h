#pragma once

#include <stdbool.h>
typedef unsigned long irq_state_t;

static inline void disable_irq(void) {
    asm("cli");
}

static inline void enable_irq(void) {
    asm("sti");
}

static inline irq_state_t x86_64_get_irq_state(void) {
    irq_state_t state;
    asm volatile("pushfq; pop %0" : "=r"(state));
    return state;
}

static inline irq_state_t save_disable_irq(void) {
    irq_state_t state = x86_64_get_irq_state();
    disable_irq();
    return state;
}

static inline void restore_irq(irq_state_t state) {
    if (state & 0x200) enable_irq();
}
