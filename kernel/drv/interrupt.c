#include "drv/interrupt.h"
#include "arch/irq.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "proc/sched.h"
#include "string.h"
#include "util/eventqueue.h"
#include "util/list.h"
#include "util/object.h"
#include "util/printk.h"
#include "util/spinlock.h"
#include <hydrogen/eventqueue.h>
#include <hydrogen/interrupt.h>

#define IRQ_WAIT_FLAGS (HYDROGEN_IRQ_WAIT_CLAIM)

void interrupt_init(interrupt_t *irq, const interrupt_ops_t *ops) {
    irq->base.ops = &ops->base;
    obj_init(&irq->base, OBJECT_INTERRUPT);
    irq->pending = false;
    irq->id = 0;
    list_clear(&irq->waiting);
    memset(&irq->pending_source, 0, sizeof(irq->pending_source));
}

void interrupt_trigger(interrupt_t *irq) {
    preempt_state_t pstate = preempt_lock();
    irq_state_t state = spin_acq(&irq->lock);

    if (!irq->pending) {
        ((const interrupt_ops_t *)irq->base.ops)->mask(irq);
        irq->pending = true;
        event_source_signal(&irq->pending_source);

        LIST_FOREACH(irq->waiting, thread_t, wait_node, thread) {
            if (sched_wake(thread)) {
                list_remove(&irq->waiting, &thread->wait_node);
            }
        }
    } else {
        printk("irq: interrupt triggered while already pending\n");
    }

    spin_rel(&irq->lock, state);
    preempt_unlock(pstate);
}

static void do_claim(interrupt_t *irq) {
    irq->pending = false;
    irq->id += 1;
    event_source_reset(&irq->pending_source);
    ((const interrupt_ops_t *)irq->base.ops)->unmask(irq);
}

hydrogen_ret_t interrupt_wait(interrupt_t *irq, uint64_t deadline, uint32_t flags) {
    if (unlikely((flags & ~IRQ_WAIT_FLAGS) != 0)) return ret_error(EINVAL);

    irq_state_t state = spin_acq(&irq->lock);

    while (!irq->pending) {
        if (deadline == 1) {
            spin_rel(&irq->lock, state);
            return ret_error(EAGAIN);
        }

        sched_prepare_wait(true);
        list_insert_tail(&irq->waiting, &current_thread->wait_node);
        spin_rel(&irq->lock, state);
        int error = sched_perform_wait(deadline);
        state = spin_acq(&irq->lock);

        if (unlikely(error)) {
            list_remove(&irq->waiting, &current_thread->wait_node);
            spin_rel(&irq->lock, state);
            return ret_error(error);
        }
    }

    size_t id = irq->id;

    if (flags & HYDROGEN_IRQ_WAIT_CLAIM) {
        do_claim(irq);
    }

    spin_rel(&irq->lock, state);
    return ret_integer(id);
}

int interrupt_claim(interrupt_t *irq, size_t id) {
    irq_state_t state = spin_acq(&irq->lock);

    if (!irq->pending || id != irq->id) {
        spin_rel(&irq->lock, state);
        return EINVAL;
    }

    do_claim(irq);
    spin_rel(&irq->lock, state);
    return 0;
}

void interrupt_free(interrupt_t *irq) {
    event_source_cleanup(&irq->pending_source);
}

int interrupt_event_add(object_t *irq, uint32_t rights, active_event_t *event) {
    interrupt_t *self = (interrupt_t *)irq;

    switch (event->source.type) {
    case HYDROGEN_EVENT_INTERRUPT_PENDING:
        if (unlikely((rights & HYDROGEN_INTERRUPT_WAIT) == 0)) return EBADF;
        return event_source_add(&self->pending_source, event);
    default: return EINVAL;
    }
}

void interrupt_event_del(object_t *irq, active_event_t *event) {
    interrupt_t *self = (interrupt_t *)irq;

    switch (event->source.type) {
    case HYDROGEN_EVENT_INTERRUPT_PENDING: return event_source_del(&self->pending_source, event);
    default: UNREACHABLE();
    }
}
