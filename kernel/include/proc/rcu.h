#pragma once

#include "init/task.h"
#include "proc/sched.h"
#include "util/slist.h"
#include <stddef.h>

typedef struct {
    size_t generation;
    slist_t prev_cb;
    slist_t cur_cb;
    slist_t next_cb;
    task_t run_callbacks_task;
    bool task_queued;
} rcu_cpu_state_t;

#define rcu_read_lock() preempt_lock()
#define rcu_read(value) __atomic_load_n(&(value), __ATOMIC_ACQUIRE)
#define rcu_read_unlock() preempt_unlock()

#define rcu_write(location, value) __atomic_store_n(&(location), (value), __ATOMIC_RELEASE)

INIT_DECLARE(rcu);

// These must not be called while in an RCU critical section.
void rcu_quiet(struct cpu *cpu);
void rcu_disable(void);
void rcu_enable(void);

void rcu_call(task_t *task);
void rcu_sync(void);
