#pragma once

#include "hydrogen/error.h"
#include "thread/sched.h"
#include "util/spinlock.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    char state;
    spinlock_t lock;
    thread_t *waiters;
} mutex_t;

hydrogen_error_t mutex_try_lock(mutex_t *mutex);
void mutex_lock(mutex_t *mutex);

// `timeout` has the same meaning as in `sched_wait`
hydrogen_error_t mutex_lock_timeout(mutex_t *mutex, uint64_t timeout);

void mutex_unlock(mutex_t *mutex);
