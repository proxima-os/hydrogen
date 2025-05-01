#pragma once

#include "arch/irq.h"

typedef struct {
    unsigned char state;
} spinlock_t;

irq_state_t spin_acq(spinlock_t *lock);
void spin_rel(spinlock_t *lock, irq_state_t state);

void spin_acq_noirq(spinlock_t *lock);
void spin_rel_noirq(spinlock_t *lock);
