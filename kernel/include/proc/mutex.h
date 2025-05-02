#pragma once

#include "util/list.h"
#include "util/spinlock.h"
#include <stdbool.h>

typedef struct {
    list_t waiters;
    unsigned char state;
    spinlock_t lock;
} mutex_t;

int mutex_acq(mutex_t *mutex, bool interruptible);
void mutex_rel(mutex_t *mutex);
