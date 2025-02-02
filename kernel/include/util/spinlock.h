#pragma once

#include "asm/irq.h"

typedef struct {
    unsigned char state;
} spinlock_t;

void spin_init(spinlock_t *lock);

void spin_lock_noirq(spinlock_t *lock);
void spin_unlock_noirq(spinlock_t *lock);

irq_state_t spin_lock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock, irq_state_t state);
