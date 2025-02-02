#pragma once

#include "kernel/time.h"
#include "util/spinlock.h"
#include <stdbool.h>
#include <stdint.h>

#define FS_PER_SEC 1000000000000000ul
#define NS_PER_SEC 1000000000ul

// These functions return the number of nanoseconds that have elapsed since some point in the past.
// `read_time_unlocked` must not take any locks while doing so, with the guarantee that neither versions of this
// function will be called while it is running.
extern uint64_t (*read_time)(void);
extern uint64_t (*read_time_unlocked)(void);

extern void (*timer_cleanup)(void);
extern uint64_t (*get_tsc_value)(uint64_t nanoseconds);

typedef struct timer_event {
    void (*handler)(struct timer_event *);
    uint64_t time;
    struct timer_event *prev;
    struct timer_event *next;
    struct cpu *cpu;
    spinlock_t lock;
    bool queued;
} timer_event_t;

void init_time(void);
void init_time_local(void);
void use_short_calibration(void);

timeconv_t create_timeconv(uint64_t src_freq, uint64_t dst_freq);

void event_init(timer_event_t *event, void (*handler)(struct timer_event *event));

void queue_event(timer_event_t *event);
void cancel_event(timer_event_t *event);
