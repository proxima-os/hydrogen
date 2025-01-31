#include "util/spinlock.h"
#include "asm/idle.h"
#include <stdbool.h>

#define SPIN_UNLOCKED 0
#define SPIN_LOCKED 1

static bool try_lock(spinlock_t *lock) {
    return __atomic_exchange_n(&lock->state, SPIN_LOCKED, __ATOMIC_ACQUIRE) == SPIN_UNLOCKED;
}

void spin_lock_noirq(spinlock_t *lock) {
    while (!try_lock(lock)) {
        cpu_relax();
    }
}

void spin_unlock_noirq(spinlock_t *lock) {
    __atomic_store_n(&lock->state, SPIN_UNLOCKED, __ATOMIC_RELEASE);
}

irq_state_t spin_lock(spinlock_t *lock) {
    irq_state_t state = save_disable_irq();

    if (state & 0x200) {
        while (!try_lock(lock)) {
            enable_irq();
            cpu_relax();
            disable_irq();
        }
    } else {
        spin_lock_noirq(lock);
    }

    return state;
}

void spin_unlock(spinlock_t *lock, irq_state_t state) {
    spin_unlock_noirq(lock);
    restore_irq(state);
}
