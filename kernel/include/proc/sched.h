#pragma once

#include "arch/context.h"
#include "arch/sched.h"
#include "hydrogen/signal.h"
#include "mem/vmm.h"
#include "proc/process.h"
#include "proc/signal.h"
#include "util/list.h"
#include "util/object.h"
#include "util/slist.h"
#include "util/spinlock.h"
#include "util/time.h"
#include <stdbool.h>
#include <stdint.h>

typedef bool preempt_state_t;
typedef bool migrate_state_t;

struct namespace;

typedef enum {
    THREAD_CREATED,
    THREAD_RUNNING,
    THREAD_BLOCKED,
    THREAD_BLOCKED_INTERRUPTIBLE,
    THREAD_EXITING,
    THREAD_EXITED,
} thread_state_t;

typedef struct thread {
    object_t base;
    pid_t *pid;
    struct cpu *cpu;
    list_node_t queue_node;
    list_node_t wait_node;
    arch_thread_t arch;
    void *stack;
    vmm_t *vmm;
    process_t *process;
    struct namespace *namespace;
    arch_context_t *user_ctx;
    list_node_t process_node;
    thread_state_t state;
    timer_event_t timeout_event;
    int wake_status;
    int exit_status;
    spinlock_t cpu_lock;
    bool active;
    bool user_thread;
    bool interrupted;
    signal_target_t sig_target;
    __sigset_t sig_mask;
    __stack_t sig_stack;
    queued_signal_t fault_sig;
} thread_t;

typedef struct task {
    slist_node_t node;
    void (*func)(struct task *self);
} task_t;

typedef struct {
    list_t queue;
    size_t num_threads;
    thread_t *current;
    thread_t *reaper;
    list_t reaper_queue;
    thread_t idle_thread;
    preempt_state_t preempt_state;
    bool preempt_queued;
    bool preempt_work;
    spinlock_t lock;
    slist_t tasks;
} sched_t;

void sched_init(void);
void sched_init_late(void);

#define THREAD_USER (1u << 0)

// creates a thread in the THREAD_CREATED state with 1 reference
// if `cpu` isn't `NULL`, the thread is pinned on the specified cpu
// user-mode state will be copied from the current thread
int sched_create_thread(
        thread_t **out,
        void (*func)(void *),
        void *ctx,
        struct cpu *cpu,
        process_t *process,
        unsigned flags
);

preempt_state_t preempt_lock(void);
void preempt_unlock(preempt_state_t state);

void sched_yield(void);
bool sched_wake(thread_t *thread); // if thread is in THREAD_CREATED, increments its reference count
bool sched_interrupt(thread_t *thread, bool force_user_transition);

void sched_prepare_wait(bool interruptible);
int sched_perform_wait(uint64_t deadline);
void sched_cancel_wait(void);
_Noreturn void sched_exit(int status);
void sched_migrate(struct cpu *dest);

void sched_queue_task(task_t *task);
_Noreturn void sched_idle(void);

// note: migration locks only prevent automatic migration. explicit migrations
// via sched_migrate are still allowed.
migrate_state_t migrate_lock(void);
void migrate_unlock(migrate_state_t state);

void *alloc_kernel_stack(void);
void free_kernel_stack(void *stack);

// the following functions are internal to the scheduler

_Noreturn void sched_init_thread(thread_t *prev, void (*func)(void *), void *ctx);

// returns the thread that was switched from. called with interrupts and preemption disabled.
thread_t *arch_switch_thread(thread_t *from, thread_t *to);
int arch_init_thread(arch_thread_t *thread, void (*func)(void *), void *ctx, void *stack, unsigned flags);
void arch_reap_thread(arch_thread_t *thread);
