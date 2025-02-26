#pragma once

#include "hydrogen/error.h"
#include "time/time.h"
#include "util/object.h"
#include "util/spinlock.h"
#include <stddef.h>
#include <stdint.h>

typedef struct address_space address_space_t;
typedef struct cpu cpu_t;
typedef struct sched sched_t;
typedef struct thread thread_t;

/* Allowed state transitions:
 * - `THREAD_CREATED` -> `THREAD_RUNNING`, `THREAD_EXITED` (by any thread)
 * - `THREAD_RUNNING` -> `THREAD_WAITING`, `THREAD_EXITING` (by the thread itself)
 * - `THREAD_WAITING` -> `THREAD_RUNNING` (by any thread)
 * - `THREAD_EXITING` -> `THREAD_EXITED` (by the reaper thread)
 */
typedef enum {
    THREAD_CREATED,
    THREAD_RUNNING,
    THREAD_WAITING,
    THREAD_EXITING,
    THREAD_EXITED,
} thread_state_t;

typedef enum {
    WAKE_EXPLICIT,
    WAKE_TIMEOUT,
} wake_reason_t;

typedef struct {
    size_t rbx;
    size_t rbp;
    size_t r12;
    size_t r13;
    size_t r14;
    size_t r15;
    size_t rip;
} thread_regs_t;

struct thread {
    object_t base;
    sched_t *sched;
    thread_t *next;
    thread_state_t state;
    thread_regs_t *regs;
    void *stack;
    void *xsave;
    uint16_t ds, es, fs, gs;
    uintptr_t fsbase;
    uintptr_t gsbase;
    timer_event_t timeout_event;
    wake_reason_t wake_reason;
    bool preempted;
    thread_t *priv_prev;
    thread_t *priv_next;
    address_space_t *address_space;
};

struct sched {
    thread_t *current;
    struct {
        spinlock_t lock;
        thread_t *first;
        thread_t *last; // only valid if first != NULL
    } queue;
    thread_t *reaper;
    thread_t *reap_queue;
    thread_t idle;
    size_t threads;
    unsigned preempt;
};

typedef void (*thread_func_t)(void *);

void init_sched_global(void);
void init_sched_early(void);
void init_sched_late(void);
_Noreturn void sched_idle(void);

// Creates a thread in the `THREAD_CREATED` state.
hydrogen_error_t sched_create(thread_t **out, thread_func_t func, void *ctx, cpu_t *cpu);

void sched_yield(void);
void sched_migrate(cpu_t *dest);

void sched_disable_preempt(void);
void sched_enable_preempt(void);

// `THREAD_CREATED`, `THREAD_WAITING` -> `THREAD_RUNNING`
void sched_wake(thread_t *thread);

// `THREAD_RUNNING` -> `THREAD_WAITING`
// `timeout` is the value of `read_time()` at which the wait should time out. 0 is infinity.
// if `lock` is non-NULL, it is unlocked in a way that prevents lost wakeups. it must be re-locked manually.
hydrogen_error_t sched_wait(uint64_t timeout, spinlock_t *lock);

// `THREAD_RUNNING` -> `THREAD_EXITING`
_Noreturn void sched_exit(void);

void *alloc_kernel_stack(void);
void free_kernel_stack(void *stack);
