#include "proc/mutex.h"
#include "cpu/cpudata.h"
#include "kernel/compiler.h"
#include "proc/sched.h"
#include "util/list.h"
#include "util/spinlock.h"
#include <stdbool.h>

#define MUTEX_UNLOCKED 0
#define MUTEX_LOCKED 1
#define MUTEX_CONTESTED 2

#define SPIN_ITERS 40

static bool try_lock_weak(mutex_t *mutex) {
    unsigned char wanted = MUTEX_UNLOCKED;
    return __atomic_compare_exchange_n(&mutex->state, &wanted, MUTEX_LOCKED, true, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

int mutex_acq(mutex_t *mutex, uint64_t deadline, bool interruptible) {
    if (likely(try_lock_weak(mutex))) return 0;

    for (int i = 0; i < SPIN_ITERS; i++) {
        sched_yield();
        if (likely(try_lock_weak(mutex))) return 0;
    }

    preempt_state_t state = preempt_lock();
    spin_acq_noirq(&mutex->lock);

    int status = 0;

    if (__atomic_exchange_n(&mutex->state, MUTEX_CONTESTED, __ATOMIC_ACQUIRE) == MUTEX_LOCKED) {
        list_insert_tail(&mutex->waiters, &current_thread->wait_node);
        sched_prepare_wait(interruptible);
        spin_rel_noirq(&mutex->lock);
        status = sched_perform_wait(deadline);
        spin_acq_noirq(&mutex->lock);

        if (status) {
            list_remove(&mutex->waiters, &current_thread->wait_node);

            if (list_empty(&mutex->waiters)) {
                // correct mutex state if it's still locked
                // note that this must be a cmpxchg, since while we do own the mutex spinlock,
                // we do not own the mutex itself
                unsigned char wanted = MUTEX_CONTESTED;
                __atomic_compare_exchange_n(
                        &mutex->state,
                        &wanted,
                        MUTEX_LOCKED,
                        false,
                        __ATOMIC_RELAXED,
                        __ATOMIC_RELAXED
                );
            }
        }
    } else {
        // this isn't racy because we own the spinlock
        __atomic_store_n(&mutex->state, MUTEX_LOCKED, __ATOMIC_RELAXED);
    }

    spin_rel_noirq(&mutex->lock);
    preempt_unlock(state);
    return status;
}

void mutex_rel(mutex_t *mutex) {
    unsigned char value = MUTEX_LOCKED;
    if (likely(__atomic_compare_exchange_n(
                &mutex->state,
                &value,
                MUTEX_UNLOCKED,
                false,
                __ATOMIC_RELEASE,
                __ATOMIC_RELAXED
        ))) {
        return;
    }

    ASSERT(value == MUTEX_CONTESTED);

    preempt_state_t state = preempt_lock();
    spin_acq_noirq(&mutex->lock);

    LIST_FOREACH(mutex->waiters, thread_t, wait_node, waiter) {
        if (sched_wake(waiter)) {
            list_remove(&mutex->waiters, &waiter->wait_node);
            if (list_empty(&mutex->waiters)) __atomic_store_n(&mutex->state, MUTEX_LOCKED, __ATOMIC_RELEASE);
            goto done;
        }
    }

    // all the waiters were interrupted/timed out
    __atomic_store_n(&mutex->state, MUTEX_UNLOCKED, __ATOMIC_RELEASE);
done:
    spin_rel_noirq(&mutex->lock);
    preempt_unlock(state);
}
