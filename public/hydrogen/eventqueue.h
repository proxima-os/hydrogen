/** \file
 * Definitions for event queues.
 *
 * Note that event queues do not keep objects alive. If the last handle to an object is removed
 * while it is still in an event queue, it is removed from said queue.
 */
#ifndef HYDROGEN_EVENTQUEUE_H
#define HYDROGEN_EVENTQUEUE_H

#include "hydrogen/types.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HYDROGEN_EVENT_QUEUE_ADD (1u << 0)    /**< Allow event sources to be added to the queue. */
#define HYDROGEN_EVENT_QUEUE_REMOVE (1u << 1) /**< Allow event sources to be added to the queue. */
#define HYDROGEN_EVENT_QUEUE_WAIT (1u << 2)   /**< Allow the queue to be waited on. */

typedef enum {
    /**
     * Active when a process has a pending signal. Requires #HYDROGEN_PROCESS_WAIT_SIGNAL.
     * The input data is the signal mask, the output data is the pending set.
     */
    HYDROGEN_EVENT_PROCESS_SIGNAL,
    /**
     * Active when a process has status information available. Requires #HYDROGEN_PROCESS_WAIT_STATUS.
     * The input data is a bitmask allowing the following flags:
     * - #HYDROGEN_PROCESS_WAIT_EXITED
     * - #HYDROGEN_PROCESS_WAIT_KILLED
     * - #HYDROGEN_PROCESS_WAIT_STOPPED
     * - #HYDROGEN_PROCESS_WAIT_CONTINUED
     * The output data is the status type (in the upper 32 bits) and status value (in the lower 32 bits).
     */
    HYDROGEN_EVENT_PROCESS_STATUS,
} hydrogen_event_type_t;

typedef struct {
    hydrogen_event_type_t type; /**< The type of the event. */
    uint32_t flags;             /**< The event output flags. */
    uint64_t data;              /**< Event-specific data. */
    void *ctx;                  /**< The `ctx` parameter that was passed to #hydrogen_event_queue_add. */
} hydrogen_event_t;

/**
 * Create an event queue.
 *
 * \param[in] flags The flags that should be set on the returned handle.
 * \return A handle to the newly created event queue (in `integer`).
 */
hydrogen_ret_t hydrogen_event_queue_create(uint32_t flags) __asm__("__hydrogen_event_queue_create");

/**
 * Add an event source to an event queue.
 *
 * Within a given event queue, there may only be one source for each combination of (object,event,data).
 * If this call would add another, it fails with #EEXIST.
 *
 * \param[in] queue The queue that the event source should be added to. Requires #HYDROGEN_EVENT_QUEUE_ADD.
 * \param[in] object The object that will be listened on.
 * \param[in] event The event to listen for.
 * \param[in] data Event-specific data.
 * \param[in] ctx Opaque data to be returned when the event occurs.
 * \param[in] flags Flags that should be set for this event source.
 * \result 0, if successful; if not, an error code.
 */
int hydrogen_event_queue_add(
        int queue,
        int object,
        hydrogen_event_type_t event,
        uint64_t data,
        void *ctx,
        uint32_t flags
) __asm__("__hydrogen_event_queue_add");

/**
 * Remove an event source from an event queue.
 *
 * \param[in] queue The queue that the event source should be removed from. Requires #HYDROGEN_EVENT_QUEUE_REMOVE.
 * \param[in] object The object that the event source listens on.
 * \param[in] event The event that the event source listens for.
 * \param[in] data The event-specific data that the event source was registered with.
 * \return The `ctx` parameter corresponding to the event (in `pointer`).
 */
hydrogen_ret_t hydrogen_event_queue_remove(int queue, int object, hydrogen_event_type_t event, uint64_t data) __asm__(
        "__hydrogen_event_queue_remove"
);

/**
 * Wait for events in an event queue.
 *
 * \param[in] queue The queue that should be waited on. Requires #HYDROGEN_EVENT_SOURCE_WAIT.
 * \param[out] events The buffer that events should be returned in.
 * \param[in] count The number of slots in `events`. Zero is legal; this makes the call simply wait until any events are
 *                  pending, without returning any information about said events.
 * \param[in] deadline The boot time value at which the wait should stop. If zero, wait forever. If one, do not wait.
 *                     If the deadline is reached, this call returns #EAGAIN.
 * \return The number of events that were returned (in `integer`).
 */
hydrogen_ret_t hydrogen_event_queue_wait(int queue, hydrogen_event_t *events, size_t count, uint64_t deadline) __asm__(
        "__hydrogen_event_queue_wait"
);

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_EVENTQUEUE_H */
