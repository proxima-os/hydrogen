#pragma once

#include "util/list.h"
#include "util/spinlock.h"
#include <stdint.h>

typedef struct {
    list_t waiters;
    bool signalled;
    spinlock_t lock;
} event_t;

void event_signal(event_t *event);
void event_clear(event_t *event);
int event_wait(event_t *event, uint64_t deadline, bool interruptible);
