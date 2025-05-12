#pragma once

#include "util/list.h"
#include "util/spinlock.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    list_t waiters;
    unsigned char state;
    spinlock_t lock;
} mutex_t;

typedef struct {
    mutex_t base;
    struct thread *owner;
    size_t levels;
} rmutex_t;

int mutex_acq(mutex_t *mutex, uint64_t deadline, bool interruptible);
bool mutex_try_acq(mutex_t *mutex);
void mutex_rel(mutex_t *mutex);

int rmutex_acq(rmutex_t *mutex, uint64_t deadline, bool interruptible);
void rmutex_rel(rmutex_t *mutex);
