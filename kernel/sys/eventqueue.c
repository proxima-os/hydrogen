#include "hydrogen/eventqueue.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "sys/syscall.h"
#include "util/eventqueue.h"
#include "util/handle.h"
#include "util/object.h"
#include <stdint.h>

#define EVENT_QUEUE_RIGHTS (HYDROGEN_EVENT_QUEUE_ADD | HYDROGEN_EVENT_QUEUE_REMOVE | HYDROGEN_EVENT_QUEUE_WAIT)

hydrogen_ret_t hydrogen_event_queue_create(uint32_t flags) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return ret_error(EINVAL);

    event_queue_t *queue;
    int error = event_queue_create(&queue);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = hnd_alloc(&queue->base, EVENT_QUEUE_RIGHTS, flags);
    obj_deref(&queue->base);
    return ret;
}

int hydrogen_event_queue_add(
        int queue,
        int object,
        hydrogen_event_type_t event,
        uint64_t data,
        void *ctx,
        uint32_t flags
) {
    handle_data_t qdata;
    int error = hnd_resolve(&qdata, queue, OBJECT_EVENT_QUEUE, HYDROGEN_EVENT_QUEUE_ADD);
    if (unlikely(error)) return error;

    handle_data_t obj;
    error = namespace_resolve(&obj, current_thread->namespace, object);
    if (unlikely(error)) goto ret;

    error = event_queue_add((event_queue_t *)qdata.object, obj.object, obj.rights, event, data, ctx, flags);
    obj_deref(obj.object);
ret:
    obj_deref(qdata.object);
    return error;
}

hydrogen_ret_t hydrogen_event_queue_remove(int queue, int object, hydrogen_event_type_t event, uint64_t data) {
    handle_data_t qdata;
    int error = hnd_resolve(&qdata, queue, OBJECT_EVENT_QUEUE, HYDROGEN_EVENT_QUEUE_REMOVE);
    if (unlikely(error)) return ret_error(error);

    handle_data_t obj;
    error = namespace_resolve(&obj, current_thread->namespace, object);
    if (unlikely(error)) {
        obj_deref(qdata.object);
        return ret_error(error);
    }

    hydrogen_ret_t ret = event_queue_remove((event_queue_t *)qdata.object, obj.object, event, data);
    obj_deref(obj.object);
    obj_deref(qdata.object);
    return ret;
}

hydrogen_ret_t hydrogen_event_queue_wait(int queue, hydrogen_event_t *events, size_t count, uint64_t deadline) {
    int error = verify_user_buffer(events, sizeof(*events) * count);
    if (unlikely(error)) return ret_error(error);

    handle_data_t qdata;
    error = hnd_resolve(&qdata, queue, OBJECT_EVENT_QUEUE, HYDROGEN_EVENT_QUEUE_WAIT);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = event_queue_wait((event_queue_t *)qdata.object, events, count, deadline);
    obj_deref(qdata.object);
    return ret;
}
