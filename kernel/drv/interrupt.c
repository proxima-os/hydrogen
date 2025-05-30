#include "drv/interrupt.h"
#include "arch/irq.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "fs/vfs.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "proc/sched.h"
#include "string.h"
#include "sys/interrupt.h"
#include "util/eventqueue.h"
#include "util/handle.h"
#include "util/list.h"
#include "util/object.h"
#include "util/printk.h"
#include "util/refcount.h"
#include "util/spinlock.h"
#include <hydrogen/eventqueue.h>
#include <hydrogen/interrupt.h>
#include <hydrogen/ioctl-data.h>
#include <hydrogen/ioctl.h>

#define IRQ_WAIT_FLAGS (HYDROGEN_IRQ_WAIT_COMPLETE)

static void interrupt_free(object_t *ptr) {
    interrupt_t *irq = (interrupt_t *)ptr;

    irq->controller->ops->close(irq->controller, irq->irq);
    event_source_cleanup(&irq->pending_source);

    if (irq->pending) {
        printk("interrupt: irq object was freed while pending\n");
    }

    vfree(irq, sizeof(*irq));
}

static int interrupt_event_add(object_t *irq, uint32_t rights, active_event_t *event) {
    interrupt_t *self = (interrupt_t *)irq;

    switch (event->source.type) {
    case HYDROGEN_EVENT_INTERRUPT_PENDING:
        if (unlikely((rights & HYDROGEN_INTERRUPT_WAIT) == 0)) return EBADF;
        return event_source_add(&self->pending_source, event);
    default: return EINVAL;
    }
}

static void interrupt_event_del(object_t *irq, active_event_t *event) {
    interrupt_t *self = (interrupt_t *)irq;

    switch (event->source.type) {
    case HYDROGEN_EVENT_INTERRUPT_PENDING: return event_source_del(&self->pending_source, event);
    default: UNREACHABLE();
    }
}

static const object_ops_t irq_object_ops = {
    .free = interrupt_free,
    .event_add = interrupt_event_add,
    .event_del = interrupt_event_del,
};

static void handle_user_irq(void *ptr) {
    interrupt_t *interrupt = ptr;
    spin_acq_noirq(&interrupt->lock);

    if (interrupt->pending++ == 0) {
        interrupt->controller->ops->mask(interrupt->controller, interrupt->irq);
        event_source_signal(&interrupt->pending_source);

        LIST_FOREACH(interrupt->waiting, thread_t, wait_node, thread) {
            if (sched_wake(thread)) {
                list_remove(&interrupt->waiting, &thread->wait_node);
            }
        }
    }

    spin_rel_noirq(&interrupt->lock);
}

static void irq_controller_device_file_free(object_t *ptr) {
    file_t *self = (file_t *)ptr;
    free_file(self);
    vfree(self, sizeof(*self));
}

static hydrogen_ret_t irq_controller_device_file_ioctl(file_t *self, int request, void *buffer, size_t size) {
    irq_controller_t *controller = (irq_controller_t *)self->inode->device;

    switch (request) {
    case __IOCTL_IRQ_OPEN: {
        if (unlikely((self->flags & (__O_RDONLY | __O_WRONLY)) != (__O_RDONLY | __O_WRONLY))) return ret_error(EBADF);

        hydrogen_ioctl_irq_open_t data;
        if (unlikely(size < sizeof(data))) return ret_error(EINVAL);

        int error = user_memcpy(&data, buffer, sizeof(data));
        if (unlikely(error)) return ret_error(error);

        if (unlikely(data.flags & ~HANDLE_FLAGS)) return ret_error(EINVAL);

        int flags = 0;

        if (data.active_low) flags |= IRQ_ACTIVE_LOW;
        if (data.level_triggered) flags |= IRQ_LEVEL_TRIGGERED;
        if (data.shareable) flags |= IRQ_SHAREABLE;

        interrupt_t *irq = vmalloc(sizeof(*irq));
        if (unlikely(!irq)) return ret_error(ENOMEM);
        memset(irq, 0, sizeof(*irq));

        irq->base.ops = &irq_object_ops;
        obj_init(&irq->base, OBJECT_INTERRUPT);
        irq->controller = controller;

        hydrogen_ret_t ret = controller->ops->open(controller, data.irq, flags, handle_user_irq, irq);
        if (unlikely(ret.error)) return ret_error(ret.error);
        irq->irq = ret.pointer;

        ret = hnd_alloc(&irq->base, INTERRUPT_RIGHTS, data.flags);
        if (likely(!ret.error)) controller->ops->unmask(controller, irq->irq);
        obj_deref(&irq->base);

        return ret;
    }
    default: return ret_error(ENOTTY);
    }
}

static const file_ops_t irq_controller_device_file_ops = {
    .base.free = irq_controller_device_file_free,
    .ioctl = irq_controller_device_file_ioctl,
};

static hydrogen_ret_t irq_controller_device_open(
    fs_device_t *self,
    inode_t *inode,
    dentry_t *path,
    int flags,
    struct ident *ident
) {
    file_t *file = vmalloc(sizeof(*file));
    if (unlikely(!file)) return ret_error(ENOMEM);
    memset(file, 0, sizeof(*file));

    init_file(file, &irq_controller_device_file_ops, inode, path, flags);

    return ret_pointer(file);
}

static const fs_device_ops_t irq_controller_device_ops = {.open = irq_controller_device_open};

int irq_controller_init(irq_controller_t *controller) {
    memset(&controller->base, 0, sizeof(controller->base));
    controller->base.ops = &irq_controller_device_ops;
    controller->base.references = REF_INIT(1);

    return vfs_create(
        NULL,
        controller->path,
        strlen(controller->path),
        HYDROGEN_CHARACTER_DEVICE,
        0600,
        &controller->base
    );
}

static void do_complete(interrupt_t *irq) {
    if (--irq->pending == 0) {
        event_source_reset(&irq->pending_source);
        irq->controller->ops->unmask(irq->controller, irq->irq);
    }
}

int interrupt_wait(interrupt_t *irq, uint64_t deadline, uint32_t flags) {
    if (unlikely((flags & ~IRQ_WAIT_FLAGS) != 0)) return EINVAL;

    irq_state_t state = spin_acq(&irq->lock);

    while (!irq->pending) {
        if (deadline == 1) {
            spin_rel(&irq->lock, state);
            return EAGAIN;
        }

        sched_prepare_wait(true);
        list_insert_tail(&irq->waiting, &current_thread->wait_node);
        spin_rel(&irq->lock, state);
        int error = sched_perform_wait(deadline);
        state = spin_acq(&irq->lock);

        if (unlikely(error)) {
            list_remove(&irq->waiting, &current_thread->wait_node);
            spin_rel(&irq->lock, state);
            return error;
        }
    }

    if (flags & HYDROGEN_IRQ_WAIT_COMPLETE) {
        do_complete(irq);
    }

    spin_rel(&irq->lock, state);
    return 0;
}

int interrupt_complete(interrupt_t *irq) {
    irq_state_t state = spin_acq(&irq->lock);

    if (!irq->pending) {
        spin_rel(&irq->lock, state);
        return EINVAL;
    }

    do_complete(irq);
    spin_rel(&irq->lock, state);
    return 0;
}
