#include "util/spinlock.h"
#include "arch/idle.h"
#include "arch/irq.h"
#include <stdbool.h>

irq_state_t spin_acq(spinlock_t *lock) {
    irq_state_t state = save_disable_irq();
    spin_acq_noirq(lock);
    return state;
}

void spin_rel(spinlock_t *lock, irq_state_t state) {
    spin_rel_noirq(lock);
    restore_irq(state);
}

void spin_acq_noirq(spinlock_t *lock) {
    unsigned char expected = 0;

    while (__atomic_compare_exchange_n(&lock->state, &expected, 1, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        cpu_relax();
    }
}

void spin_rel_noirq(spinlock_t *lock) {
    __atomic_store_n(&lock->state, 0, __ATOMIC_RELEASE);
}
