#include "hydrogen/eventqueue.h"
#include "arch/syscall.h"
#include "hydrogen/types.h"
#include "kernel/syscall.h"
#include "vdso.h"

EXPORT hydrogen_ret_t hydrogen_event_queue_create(uint32_t flags) {
    return SYSCALL1(SYSCALL_EVENT_QUEUE_CREATE, flags);
}

EXPORT int hydrogen_event_queue_add(int queue, int object, hydrogen_event_type_t event, uint64_t data, void *ctx, uint32_t flags) {
    return SYSCALL6(SYSCALL_EVENT_QUEUE_ADD, queue, object, event, data, ctx, flags).error;
}

EXPORT hydrogen_ret_t hydrogen_event_queue_remove(int queue, int object, hydrogen_event_type_t event, uint64_t data) {
    return SYSCALL4(SYSCALL_EVENT_QUEUE_REMOVE, queue, object, event, data);
}

EXPORT hydrogen_ret_t hydrogen_event_queue_wait(int queue, hydrogen_event_t *events, size_t count, uint64_t deadline) {
    return SYSCALL4(SYSCALL_EVENT_QUEUE_WAIT, queue, events, count, deadline);
}
