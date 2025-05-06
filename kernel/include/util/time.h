#pragma once

#include "arch/time.h"
#include "kernel/time.h"
#include "util/list.h"
#include <stdint.h>

#define FS_PER_SEC 1000000000000000ull
#define NS_PER_SEC 1000000000ull

#define NS_PER_MS 1000000ull

#define NS_PER_US 1000ull

typedef struct timer_event {
    list_node_t node;
    void (*func)(struct timer_event *self);
    uint64_t deadline;
    struct cpu *cpu;
    bool running;
} timer_event_t;

// NOTE: The caller is responsible for ensuring this function is not called while
// the event is queued!
void timer_queue_event(timer_event_t *event);

void timer_cancel_event(timer_event_t *event);

timeconv_t timeconv_create(uint64_t src_freq, uint64_t dst_freq);

void arch_queue_timer_irq(uint64_t deadline);
void time_handle_irq(void);

static inline void time_stall(uint64_t nanoseconds) {
    uint64_t start = arch_read_time();

    for (;;) {
        if (arch_read_time() - start >= nanoseconds) return;
    }
}
