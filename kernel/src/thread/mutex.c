#include "thread/mutex.h"
#include "cpu/cpu.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "thread/sched.h"
#include "util/panic.h"

#define SPIN_ITERS 40

#define MUTEX_UNLOCKED 0
#define MUTEX_LOCKED 1
#define MUTEX_CONTESTED 2

int mutex_try_lock(mutex_t *mutex) {
    char wanted = MUTEX_UNLOCKED;
    return __atomic_compare_exchange_n(&mutex->state, &wanted, MUTEX_LOCKED, false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)
                   ? 0
                   : EBUSY;
}

void mutex_lock(mutex_t *mutex) {
    UNUSED int error = mutex_lock_timeout(mutex, 0);
    ASSERT(!error);
}

static bool try_lock_weak(mutex_t *mutex) {
    char wanted = MUTEX_UNLOCKED;

    return __atomic_compare_exchange_n(&mutex->state, &wanted, MUTEX_LOCKED, true, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
}

int mutex_lock_timeout(mutex_t *mutex, uint64_t timeout) {
    if (likely(try_lock_weak(mutex))) return 0;

    for (int i = 0; i < SPIN_ITERS; i++) {
        if (likely(try_lock_weak(mutex))) return 0;

        sched_yield();
    }

    irq_state_t state = spin_lock(&mutex->lock);

    int error;

    if (likely(__atomic_exchange_n(&mutex->state, MUTEX_CONTESTED, __ATOMIC_ACQ_REL) != MUTEX_UNLOCKED)) {
        current_thread->priv_prev = NULL;
        current_thread->priv_next = mutex->waiters;
        mutex->waiters = current_thread;
        if (current_thread->priv_next) current_thread->priv_next->priv_prev = current_thread;

        error = sched_wait(timeout, &mutex->lock);

        if (unlikely(error)) {
            if (current_thread->priv_prev) current_thread->priv_prev->priv_next = current_thread->priv_next;
            else mutex->waiters = current_thread->priv_next;

            if (current_thread->priv_next) current_thread->priv_next->priv_prev = current_thread->priv_prev;
        }
    } else {
        // not racy because we own the spinlock
        __atomic_store_n(&mutex->state, MUTEX_LOCKED, __ATOMIC_RELEASE);
        error = 0;
    }

    spin_unlock(&mutex->lock, state);
    return error;
}

void mutex_unlock(mutex_t *mutex) {
    char wanted = MUTEX_LOCKED;
    if (likely(__atomic_compare_exchange_n(
                &mutex->state,
                &wanted,
                MUTEX_UNLOCKED,
                false,
                __ATOMIC_ACQ_REL,
                __ATOMIC_RELAXED
        ))) {
        return;
    }

    // If it's neither this nor MUTEX_LOCKED, someone else unlocked the mutex even though we owned it
    // Note that a mutex can only be moved off of CONTESTED by the owner of the lock (us) calling mutex_unlock
    ASSERT(wanted == MUTEX_CONTESTED);

    irq_state_t state = save_disable_irq();
    sched_disable_preempt();
    spin_lock_noirq(&mutex->lock);

    thread_t *thread = mutex->waiters;

    if (thread) {
        mutex->waiters = thread->priv_next;

        if (mutex->waiters) {
            mutex->waiters->priv_prev = NULL;
        } else {
            __atomic_store_n(&mutex->state, MUTEX_LOCKED, __ATOMIC_RELEASE);
        }

        sched_wake(thread);
    } else {
        __atomic_store_n(&mutex->state, MUTEX_UNLOCKED, __ATOMIC_RELEASE);
    }

    spin_unlock_noirq(&mutex->lock);
    sched_enable_preempt();
    restore_irq(state);
}
