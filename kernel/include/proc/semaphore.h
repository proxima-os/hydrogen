#pragma once

#include "proc/mutex.h"
#include "util/list.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    mutex_t lock;
    size_t count;
    list_t waiting;
} semaphore_t;

bool sema_try_wait(semaphore_t *sema);
int sema_wait(semaphore_t *sema, uint64_t deadline, bool interruptible);
void sema_signal(semaphore_t *sema);
void sema_reset(semaphore_t *sema);
