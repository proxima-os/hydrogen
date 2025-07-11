#include "proc/event.h"
#include "arch/irq.h"
#include "cpu/cpudata.h"
#include "proc/sched.h"
#include "util/list.h"
#include "util/spinlock.h"
#include <stdint.h>

void event_signal(event_t *event) {
    bool wanted = false;

    if (__atomic_compare_exchange_n(&event->signalled, &wanted, true, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
        preempt_lock();
        irq_state_t state = spin_acq(&event->lock);

        thread_t *waiter = LIST_HEAD(event->waiters, thread_t, wait_nodes[0]);

        while (waiter) {
            thread_t *next = LIST_NEXT(*waiter, thread_t, wait_nodes[0]);

            if (sched_wake(waiter)) {
                list_remove(&event->waiters, &waiter->wait_nodes[0]);
            }

            waiter = next;
        }

        spin_rel(&event->lock, state);
        preempt_unlock();
    }
}

void event_clear(event_t *event) {
    __atomic_store_n(&event->signalled, false, __ATOMIC_RELEASE);
}

int event_wait(event_t *event, uint64_t deadline, bool interruptible) {
    if (__atomic_load_n(&event->signalled, __ATOMIC_ACQUIRE)) return 0;

    int status = 0;
    irq_state_t state = spin_acq(&event->lock);

    // check signalled again, it might have been changed before we got the lock
    if (!__atomic_load_n(&event->signalled, __ATOMIC_ACQUIRE)) {
        // if signalled changes now, it doesn't matter, the one who changed it still
        // needs to get the lock before they can wake up everyone
        list_insert_tail(&event->waiters, &current_thread->wait_nodes[0]);
        sched_prepare_wait(interruptible);
        spin_rel(&event->lock, state);
        status = sched_perform_wait(deadline);
        state = spin_acq(&event->lock);
        if (status) list_remove(&event->waiters, &current_thread->wait_nodes[0]);
    }

    spin_rel(&event->lock, state);
    return status;
}
