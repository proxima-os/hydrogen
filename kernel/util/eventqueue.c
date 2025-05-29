#include "util/eventqueue.h"
#include "arch/irq.h"
#include "arch/time.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "proc/mutex.h"
#include "proc/sched.h"
#include "string.h"
#include "util/hash.h"
#include "util/hlist.h"
#include "util/list.h"
#include "util/object.h"
#include "util/spinlock.h"
#include <hydrogen/eventqueue.h>
#include <stdint.h>

#define EVENT_INPUT_FLAGS (HYDROGEN_EVENT_NO_WAKE)

static void event_queue_free(object_t *ptr) {
    event_queue_t *self = (event_queue_t *)ptr;

    // need to lock here because, as long as we have events, their sources might have references
    // to us that aren't counted
    mutex_acq(&self->lock, 0, false);

    for (;;) {
        active_event_t *event = LIST_REMOVE_HEAD(self->events, active_event_t, node);
        if (!event) break;

        event->source.object->ops->event_del(event->source.object, event);
        vfree(event, sizeof(*event));
    }

    mutex_rel(&self->lock);
    vfree(self->table, self->table_capacity * sizeof(*self->table));
    vfree(self, sizeof(*self));
}

static const object_ops_t event_queue_ops = {.free = event_queue_free};

int event_queue_create(event_queue_t **out) {
    event_queue_t *queue = vmalloc(sizeof(*queue));
    if (unlikely(!queue)) return ENOMEM;
    memset(queue, 0, sizeof(*queue));

    queue->base.ops = &event_queue_ops;
    obj_init(&queue->base, OBJECT_EVENT_QUEUE);

    *out = queue;
    return 0;
}

static active_event_t *get_active_event(event_queue_t *queue, const event_source_id_t *id, uint64_t hash) {
    if (!queue->table_capacity) return NULL;

    active_event_t *event = LIST_HEAD(queue->table[hash & (queue->table_capacity - 1)], active_event_t, table_node);

    while (event != NULL && (event->hash != hash || memcmp(&event->source, id, sizeof(*id)))) {
        event = LIST_NEXT(*event, active_event_t, table_node);
    }

    return event;
}

static int maybe_expand(event_queue_t *queue) {
    if (queue->table_count < queue->table_capacity - (queue->table_capacity / 4)) return 0;

    size_t new_cap = queue->table_capacity ? queue->table_capacity * 2 : 8;
    size_t new_siz = new_cap * sizeof(*queue->table);
    hlist_t *new_table = vmalloc(new_siz);
    if (unlikely(!new_table)) return ENOMEM;
    memset(new_table, 0, new_siz);

    for (size_t i = 0; i < queue->table_capacity; i++) {
        for (;;) {
            active_event_t *event = HLIST_REMOVE_HEAD(queue->table[i], active_event_t, table_node);
            if (!event) break;
            hlist_insert_head(&new_table[event->hash & (new_cap - 1)], &event->table_node);
        }
    }

    vfree(queue->table, queue->table_capacity * sizeof(*queue->table));
    queue->table = new_table;
    queue->table_capacity = new_cap;
    return 0;
}

int event_queue_add(
    event_queue_t *queue,
    object_t *object,
    object_rights_t rights,
    hydrogen_event_type_t type,
    uint64_t data,
    void *ctx,
    uint32_t flags
) {
    if (unlikely((flags & ~EVENT_INPUT_FLAGS) != 0)) return EINVAL;
    if (unlikely(object->ops->event_add == NULL)) return EINVAL;

    event_source_id_t id = {.object = object, .type = type, .data = data};
    uint64_t hash = make_hash_blob(&id, sizeof(id));
    mutex_acq(&queue->lock, 0, false);

    active_event_t *event = get_active_event(queue, &id, hash);

    if (unlikely(event != NULL)) {
        mutex_rel(&queue->lock);
        return EEXIST;
    }

    event = vmalloc(sizeof(*event));

    if (unlikely(event == NULL)) {
        mutex_rel(&queue->lock);
        return ENOMEM;
    }

    memset(event, 0, sizeof(*event));
    event->queue = queue;
    event->source = id;
    event->hash = hash;
    event->ctx = ctx;
    event->flags = flags;

    int error = object->ops->event_add(object, rights, event);

    if (unlikely(error)) {
        mutex_rel(&queue->lock);
        vfree(event, sizeof(*event));
        return error;
    }

    error = maybe_expand(queue);

    if (unlikely(error)) {
        object->ops->event_del(object, event);
        mutex_rel(&queue->lock);
        vfree(event, sizeof(*event));
        return error;
    }

    hlist_insert_head(&queue->table[event->hash & (queue->table_capacity - 1)], &event->table_node);
    list_insert_tail(&queue->events, &event->node);
    queue->table_count += 1;

    mutex_rel(&queue->lock);
    return 0;
}

static void do_remove_event(event_queue_t *queue, active_event_t *event) {
    event->source.object->ops->event_del(event->source.object, event);
    hlist_remove(&queue->table[event->hash & (queue->table_capacity - 1)], &event->table_node);
    list_remove(&queue->events, &event->node);
    vfree(event, sizeof(*event));
    queue->table_count -= 1;
}

hydrogen_ret_t event_queue_remove(event_queue_t *queue, object_t *object, hydrogen_event_type_t type, uint64_t data) {
    event_source_id_t id = {.object = object, .type = type, .data = data};
    uint64_t hash = make_hash_blob(&id, sizeof(id));
    mutex_acq(&queue->lock, 0, false);

    active_event_t *event = get_active_event(queue, &id, hash);

    if (unlikely(!event)) {
        mutex_rel(&queue->lock);
        return ret_error(ENOENT);
    }

    void *ctx = event->ctx;
    do_remove_event(queue, event);
    mutex_rel(&queue->lock);
    return ret_pointer(ctx);
}

hydrogen_ret_t event_queue_wait(event_queue_t *queue, hydrogen_event_t *events, size_t count, uint64_t deadline) {
    irq_state_t state = spin_acq(&queue->pending_lock);

retry:
    while (queue->num_waking == 0) {
        if (deadline != 0 && deadline <= arch_read_time()) {
            spin_rel(&queue->pending_lock, state);
            return ret_error(EAGAIN);
        }

        list_insert_tail(&queue->waiting, &current_thread->wait_node);
        sched_prepare_wait(true);
        spin_rel(&queue->pending_lock, state);
        int error = sched_perform_wait(deadline);
        state = spin_acq(&queue->pending_lock);
        list_remove(&queue->waiting, &current_thread->wait_node);

        if (unlikely(error)) {
            spin_rel(&queue->pending_lock, state);
            return ret_error(error == ETIMEDOUT ? EAGAIN : error);
        }
    }

    size_t num_returned = 0;
    active_event_t *event = LIST_HEAD(queue->pending, active_event_t, pending_node);

    while (event != NULL && num_returned < count) {
        hydrogen_event_t data = {.type = event->source.type, .ctx = event->ctx};
        int error = user_memcpy(&events[num_returned], &data, sizeof(data));

        if (unlikely(error)) {
            spin_rel(&queue->pending_lock, state);
            return ret_error(error);
        }

        num_returned += 1;
        event = LIST_NEXT(*event, active_event_t, pending_node);
    }

    if (num_returned == 0 && count != 0) goto retry;

    spin_rel(&queue->pending_lock, state);
    return ret_integer(num_returned);
}

int event_source_add(event_source_t *source, active_event_t *event) {
    preempt_state_t pstate = preempt_lock();
    irq_state_t state = spin_acq(&source->lock);

    list_insert_tail(&source->events, &event->source_node);

    if (source->pending) {
        spin_acq_noirq(&event->queue->pending_lock);

        list_insert_tail(&event->queue->pending, &event->pending_node);

        if (!(event->flags & HYDROGEN_EVENT_NO_WAKE)) {
            event->queue->num_waking += 1;

            LIST_FOREACH(event->queue->waiting, thread_t, wait_node, thread) {
                sched_wake(thread);
            }
        }

        spin_rel_noirq(&event->queue->pending_lock);
    }

    spin_rel(&source->lock, state);
    preempt_unlock(pstate);
    return 0;
}

void event_source_del(event_source_t *source, active_event_t *event) {
    irq_state_t state = spin_acq(&source->lock);

    list_remove(&source->events, &event->source_node);

    if (source->pending) {
        spin_acq_noirq(&event->queue->pending_lock);
        list_remove(&event->queue->pending, &event->pending_node);
        if (!(event->flags & HYDROGEN_EVENT_QUEUE_REMOVE)) event->queue->num_waking -= 1;
        spin_rel_noirq(&event->queue->pending_lock);
    }

    spin_rel(&source->lock, state);
}

void event_source_cleanup(event_source_t *source) {
    preempt_state_t pstate = preempt_lock();
    irq_state_t state = spin_acq(&source->lock);

    for (;;) {
        active_event_t *event = LIST_HEAD(source->events, active_event_t, source_node);
        if (!event) break;

        while (!mutex_try_acq(&event->queue->lock)) {
            event_queue_t *queue = event->queue;
            obj_ref(&queue->base);
            spin_rel(&source->lock, state);
            preempt_unlock(pstate);
            mutex_acq(&queue->lock, 0, false);
            mutex_rel(&queue->lock);
            obj_deref(&queue->base);
            pstate = preempt_lock();
            state = spin_acq(&source->lock);
            event = LIST_HEAD(source->events, active_event_t, source_node);
            if (!event) break;
        }

        if (!event) break;

        hlist_remove(&event->queue->table[event->hash & (event->queue->table_capacity - 1)], &event->table_node);
        list_remove(&event->queue->events, &event->node);
        event->queue->table_count -= 1;

        mutex_rel(&event->queue->lock);

        if (source->pending) {
            spin_acq_noirq(&event->queue->pending_lock);
            list_remove(&event->queue->pending, &event->pending_node);
            if (!(event->flags & HYDROGEN_EVENT_NO_WAKE)) event->queue->num_waking -= 1;
            spin_rel_noirq(&event->queue->pending_lock);
        }

        list_remove(&source->events, &event->node);
        vfree(event, sizeof(*event));
    }

    spin_rel(&source->lock, state);
    preempt_unlock(pstate);
}

void event_source_signal(event_source_t *source) {
    if (__atomic_load_n(&source->pending, __ATOMIC_ACQUIRE)) return;

    preempt_state_t pstate = preempt_lock();
    irq_state_t state = spin_acq(&source->lock);

    if (source->pending) {
        spin_rel(&source->lock, state);
        preempt_unlock(pstate);
        return;
    }

    LIST_FOREACH(source->events, active_event_t, source_node, event) {
        spin_acq_noirq(&event->queue->pending_lock);

        list_insert_tail(&event->queue->pending, &event->pending_node);

        if (!(event->flags & HYDROGEN_EVENT_NO_WAKE)) {
            event->queue->num_waking += 1;

            LIST_FOREACH(event->queue->waiting, thread_t, wait_node, thread) {
                sched_wake(thread);
            }
        }

        spin_rel_noirq(&event->queue->pending_lock);
    }

    __atomic_store_n(&source->pending, true, __ATOMIC_RELEASE);
    spin_rel(&source->lock, state);
    preempt_unlock(pstate);
}

void event_source_reset(event_source_t *source) {
    if (!__atomic_load_n(&source->pending, __ATOMIC_ACQUIRE)) return;

    irq_state_t state = spin_acq(&source->lock);

    if (!source->pending) {
        spin_rel(&source->lock, state);
        return;
    }

    LIST_FOREACH(source->events, active_event_t, source_node, event) {
        spin_acq_noirq(&event->queue->pending_lock);
        list_remove(&event->queue->pending, &event->pending_node);
        if (!(event->flags & HYDROGEN_EVENT_NO_WAKE)) event->queue->num_waking -= 1;
        spin_rel_noirq(&event->queue->pending_lock);
    }

    __atomic_store_n(&source->pending, false, __ATOMIC_RELEASE);
    spin_rel(&source->lock, state);
}
