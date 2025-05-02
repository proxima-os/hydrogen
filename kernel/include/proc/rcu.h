#pragma once

#include "proc/sched.h"
#include "util/slist.h"
#include <stddef.h>

typedef struct {
    size_t generation;
    slist_t prev_cb;
    slist_t cur_cb;
    slist_t next_cb;
    task_t run_callbacks_task;
} rcu_cpu_state_t;

typedef preempt_state_t rcu_state_t;

#define rcu_read_lock() preempt_lock()
#define rcu_read(value) __atomic_load_n(&(value), __ATOMIC_RELAXED)
#define rcu_read_unlock(state) preempt_unlock(state)

void rcu_init(void);

void rcu_quiet(struct cpu *cpu);
void rcu_call(task_t *task);
void rcu_sync(void);
