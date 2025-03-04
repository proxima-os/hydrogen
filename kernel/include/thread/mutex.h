#pragma once

#include "util/spinlock.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct thread thread_t;

typedef struct {
    char state;
    spinlock_t lock;
    thread_t *waiters;
} mutex_t;

int mutex_try_lock(mutex_t *mutex);
void mutex_lock(mutex_t *mutex);

// `timeout` has the same meaning as in `sched_wait`
int mutex_lock_timeout(mutex_t *mutex, uint64_t timeout);

void mutex_unlock(mutex_t *mutex);
