#pragma once

#include "arch/sched.h"
#include "util/list.h"
#include "util/refcount.h"
#include "util/slist.h"
#include "util/spinlock.h"
#include <stdbool.h>
#include <stdint.h>

typedef bool preempt_state_t;

typedef enum {
    THREAD_CREATED,
    THREAD_RUNNING,
    THREAD_BLOCKED,
    THREAD_BLOCKED_INTERRUPTIBLE,
    THREAD_EXITING,
    THREAD_EXITED,
} thread_state_t;

typedef struct thread {
    refcnt_t references;
    struct cpu *cpu;
    list_node_t queue_node;
    list_node_t wait_node;
    arch_thread_t arch;
    thread_state_t state;
    int wake_status;
    spinlock_t cpu_lock;
    bool queued;
} thread_t;

typedef struct task {
    slist_node_t node;
    void (*func)(struct task *self);
} task_t;

typedef struct {
    list_t queue;
    thread_t *current;
    thread_t idle_thread;
    preempt_state_t preempt_state;
    bool preempt_queued;
    spinlock_t lock;
    slist_t tasks;
} sched_t;

void sched_init(void);

// creates a thread in the THREAD_CREATED state with 1 reference
int sched_create_thread(thread_t *thread, void (*func)(void *), void *ctx, void *stack, size_t stack_size);

preempt_state_t preempt_lock(void);
bool preempt_unlock(preempt_state_t state);

void sched_yield(void);
bool sched_wake(thread_t *thread); // if thread is in THREAD_CREATED, increments its reference count
bool sched_interrupt(thread_t *thread);

void sched_prepare_wait(bool interruptible);
int sched_perform_wait(void);
void sched_cancel_wait(void);
_Noreturn void sched_exit(void);

void thread_ref(thread_t *thread);
void thread_deref(thread_t *thread);

void sched_queue_task(task_t *task);
_Noreturn void sched_idle(void);

// the following functions are internal to the scheduler

_Noreturn void sched_init_thread(arch_thread_t *prev, void (*func)(void *), void *ctx);

// returns the thread that was switched from
arch_thread_t *arch_switch_thread(arch_thread_t *from, arch_thread_t *to);
int arch_init_thread(arch_thread_t *thread, void (*func)(void *), void *ctx, void *stack, size_t stack_size);
