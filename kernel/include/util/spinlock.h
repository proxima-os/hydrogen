#pragma once

#include "asm/irq.h"

typedef struct {
    char state;
} spinlock_t;

irq_state_t spin_lock(spinlock_t *lock);

void spin_unlock(spinlock_t *lock, irq_state_t state);

void spin_lock_noirq(spinlock_t *lock);

void spin_unlock_noirq(spinlock_t *lock);
