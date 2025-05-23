#include "proc/semaphore.h"
#include "cpu/cpudata.h"
#include "kernel/compiler.h"
#include "proc/mutex.h"
#include "proc/sched.h"
#include "util/list.h"

bool sema_try_wait(semaphore_t *sema) {
    mutex_acq(&sema->lock, 0, false);

    bool ok = sema->count > 0;
    if (ok) sema->count -= 1;

    mutex_rel(&sema->lock);
    return ok;
}

int sema_wait(semaphore_t *sema, uint64_t deadline, bool interruptible) {
    mutex_acq(&sema->lock, 0, false);

    while (sema->count == 0) {
        list_insert_tail(&sema->waiting, &current_thread->wait_node);
        sched_prepare_wait(interruptible);
        mutex_rel(&sema->lock);
        int error = sched_perform_wait(deadline);
        mutex_acq(&sema->lock, 0, false);

        if (unlikely(error)) {
            list_remove(&sema->waiting, &current_thread->wait_node);
            mutex_rel(&sema->lock);
            return error;
        }
    }

    sema->count -= 1;
    mutex_rel(&sema->lock);
    return 0;
}

void sema_signal(semaphore_t *sema) {
    mutex_acq(&sema->lock, 0, false);

    if (sema->count++ == 0) {
        thread_t *thread = LIST_HEAD(sema->waiting, thread_t, wait_node);

        while (thread) {
            thread_t *next = LIST_NEXT(*thread, thread_t, wait_node);

            if (sched_wake(thread)) {
                list_remove(&sema->waiting, &thread->wait_node);
            }

            thread = next;
        }
    }

    mutex_rel(&sema->lock);
}

void sema_reset(semaphore_t *sema) {
    mutex_acq(&sema->lock, 0, false);
    sema->count = 0;
    mutex_rel(&sema->lock);
}
