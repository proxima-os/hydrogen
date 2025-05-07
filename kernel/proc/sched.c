#include "proc/sched.h"
#include "arch/idle.h"
#include "arch/irq.h"
#include "arch/stack.h"
#include "cpu/cpudata.h"
#include "cpu/smp.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/vmalloc.h"
#include "proc/rcu.h"
#include "sections.h"
#include "string.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/refcount.h"
#include "util/slist.h"
#include "util/spinlock.h"
#include "util/time.h"
#include <stdbool.h>
#include <stdint.h>

#define PREEMPT_ENABLED 0
#define PREEMPT_DISABLED 1

static void handle_timeout_event(timer_event_t *self);

INIT_TEXT void sched_init(void) {
    cpu_t *cpu = get_current_cpu();
    sched_t *sched = &cpu->sched;
    sched->current = &sched->idle_thread;
    sched->current->references = REF_INIT(2); // one for sched->idle_thread, one for sched->current
    sched->current->cpu = cpu;
    sched->current->state = THREAD_RUNNING;
}

static void reap_thread(thread_t *thread) {
    arch_reap_thread(&thread->arch);
    free_kernel_stack(thread->stack);
    thread->state = THREAD_EXITED;
}

static void reaper_func(void *ctx) {
    cpu_t *cpu = get_current_cpu();

    for (;;) {
        irq_state_t state = save_disable_irq();
        thread_t *thread;

        for (;;) {
            thread = LIST_REMOVE_HEAD(cpu->sched.reaper_queue, thread_t, queue_node);
            if (thread != NULL) break;
            sched_prepare_wait(false);
            sched_perform_wait(0);
        }

        restore_irq(state);

        reap_thread(thread);
        thread_deref(thread);
    }
}

INIT_TEXT void sched_init_late(void) {
    cpu_t *cpu = get_current_cpu();
    int error = sched_create_thread(&cpu->sched.reaper, reaper_func, NULL, cpu);
    if (unlikely(error)) panic("sched: failed to create reaper thread (%e)", error);
}

int sched_create_thread(thread_t **out, void (*func)(void *), void *ctx, cpu_t *cpu) {
    thread_t *thread = vmalloc(sizeof(*thread));
    if (unlikely(!thread)) return ENOMEM;
    memset(thread, 0, sizeof(*thread));

    thread->stack = alloc_kernel_stack();
    if (unlikely(!thread->stack)) {
        vfree(thread, sizeof(*thread));
        return ENOMEM;
    }

    int error = arch_init_thread(&thread->arch, func, ctx, thread->stack);
    if (unlikely(error)) {
        free_kernel_stack(thread->stack);
        vfree(thread, sizeof(*thread));
        return error;
    }

    thread->references = REF_INIT(1);
    thread->cpu = cpu;
    thread->state = THREAD_CREATED;
    thread->timeout_event.func = handle_timeout_event;

    if (thread->cpu == NULL) {
        size_t cur_count = SIZE_MAX;

        SLIST_FOREACH(cpus, cpu_t, node, cpu) {
            size_t count = __atomic_load_n(&cpu->sched.num_queued, __ATOMIC_RELAXED);

            if (count < cur_count) {
                thread->cpu = cpu;
                cur_count = count;
            }
        }

        ASSERT(thread->cpu != NULL);
    }

    *out = thread;
    return 0;
}

static void do_wake(cpu_t *cpu, thread_t *thread, int status);

static void post_switch(thread_t *prev) {
    cpu_t *cpu = get_current_cpu();

    if (prev->cpu != cpu) {
        // Finish prev's migration
        spin_rel_noirq(&prev->cpu->sched.lock);
        spin_rel_noirq(&prev->cpu_lock);
    }

    if (prev->state == THREAD_EXITING) {
        list_insert_tail(&cpu->sched.reaper_queue, &prev->queue_node);

        if (cpu->sched.reaper->state != THREAD_RUNNING) {
            do_wake(cpu, cpu->sched.reaper, 0);
        }
    }
}

static void enqueue(cpu_t *cpu, thread_t *thread) {
    ASSERT(cpu == thread->cpu);

    list_insert_tail(&cpu->sched.queue, &thread->queue_node);
    __atomic_fetch_add(&cpu->sched.num_queued, 1, __ATOMIC_RELAXED);
}

static thread_t *dequeue(cpu_t *cpu) {
    thread_t *thread = LIST_REMOVE_HEAD(cpu->sched.queue, thread_t, queue_node);
    if (thread) __atomic_fetch_sub(&cpu->sched.num_queued, 1, __ATOMIC_RELAXED);
    return thread;
}

static void do_yield(cpu_t *cpu, bool migrating) {
    ASSERT(cpu == get_current_cpu());

    rcu_quiet(cpu);

    thread_t *prev = cpu->sched.current;
    if (!migrating && prev->state == THREAD_RUNNING && prev != &cpu->sched.idle_thread) {
        enqueue(cpu, prev);
    }

    thread_t *next = dequeue(cpu);
    if (!next) next = &cpu->sched.idle_thread;

    if (prev == next) return;

    cpu->sched.current = next;

    prev->active = false;
    next->active = true;

    post_switch(arch_switch_thread(prev, next));
}

static void queue_yield(cpu_t *cpu) {
    ASSERT(cpu == get_current_cpu());
    ASSERT(cpu->sched.preempt_state == PREEMPT_DISABLED);
    __atomic_store_n(&cpu->sched.preempt_queued, true, __ATOMIC_RELAXED);
}

preempt_state_t preempt_lock(void) {
    preempt_state_t state = this_cpu_read(sched.preempt_state);
    this_cpu_write(sched.preempt_state, PREEMPT_DISABLED);
    return state;
}

bool preempt_unlock(preempt_state_t state) {
    if (state == PREEMPT_ENABLED) {
        // preemption is disabled, so we don't need to worry about migration
        cpu_t *cpu = get_current_cpu();

        for (;;) {
            task_t *task = SLIST_REMOVE_HEAD(cpu->sched.tasks, task_t, node);
            if (!task) break;
            task->func(task);
        }

        irq_state_t istate = spin_acq(&cpu->sched.lock);

        bool yield = __atomic_load_n(&cpu->sched.preempt_queued, __ATOMIC_RELAXED);

        while (yield) {
            __atomic_store_n(&cpu->sched.preempt_queued, false, __ATOMIC_RELAXED);
            do_yield(cpu, false);
            cpu = get_current_cpu();
            yield = __atomic_load_n(&cpu->sched.preempt_queued, __ATOMIC_RELAXED);
        }

        __atomic_store_n(&cpu->sched.preempt_state, state, __ATOMIC_RELEASE); // avoid torn writes by using atomics
        spin_rel(&cpu->sched.lock, istate);
        return yield;
    }

    return false;
}

void sched_yield(void) {
    preempt_state_t state = preempt_lock();
    ASSERT(state == PREEMPT_ENABLED);

    cpu_t *cpu = get_current_cpu();
    irq_state_t istate = spin_acq(&cpu->sched.lock);

    ASSERT(cpu->sched.current->state == THREAD_RUNNING);
    do_yield(cpu, false);
    cpu = get_current_cpu();

    spin_rel(&cpu->sched.lock, istate);
    preempt_unlock(state);
}

static bool should_preempt(cpu_t *cpu) {
    return cpu->sched.current == &cpu->sched.idle_thread && !list_empty(&cpu->sched.queue);
}

static void remote_maybe_preempt(void *ctx) {
    cpu_t *cpu = ctx;
    ASSERT(cpu == get_current_cpu());

    if (should_preempt(cpu)) queue_yield(cpu);
}

static void maybe_preempt(cpu_t *cpu) {
    if (!should_preempt(cpu)) return;

    if (cpu == get_current_cpu()) {
        queue_yield(cpu);
    } else {
        smp_call_remote_async(cpu, remote_maybe_preempt, cpu);
    }
}

static void do_wake(cpu_t *cpu, thread_t *thread, int status) {
    ASSERT(cpu == thread->cpu);
    ASSERT(thread->state == THREAD_CREATED || thread->state == THREAD_BLOCKED ||
           thread->state == THREAD_BLOCKED_INTERRUPTIBLE);

    if (thread->state == THREAD_CREATED) thread_ref(thread);

    if (thread->timeout_event.deadline != 0) {
        timer_cancel_event(&thread->timeout_event);
        thread->timeout_event.deadline = 0;
    }

    thread->state = THREAD_RUNNING;
    thread->wake_status = status;
    if (!thread->active) enqueue(cpu, thread);
    maybe_preempt(cpu);
}

static void handle_timeout_event(timer_event_t *self) {
    thread_t *thread = CONTAINER(thread_t, timeout_event, self);
    cpu_t *cpu = thread->cpu;
    spin_acq_noirq(&cpu->sched.lock);

    if (thread->state == THREAD_BLOCKED || thread->state == THREAD_BLOCKED_INTERRUPTIBLE) {
        thread->timeout_event.deadline = 0;
        do_wake(cpu, thread, ETIMEDOUT);
    }

    spin_rel_noirq(&cpu->sched.lock);
}

bool sched_wake(thread_t *thread) {
    // need both preempt and irq lock here because sched_wake and sched_interrupt
    // are allowed to be called from irq context
    preempt_state_t pstate = preempt_lock();
    irq_state_t state = spin_acq(&thread->cpu_lock);

    cpu_t *cpu = thread->cpu;
    spin_acq_noirq(&cpu->sched.lock);

    bool wake = thread->state == THREAD_CREATED || thread->state == THREAD_BLOCKED ||
                thread->state == THREAD_BLOCKED_INTERRUPTIBLE;

    if (wake) {
        do_wake(cpu, thread, 0);
    }

    spin_rel_noirq(&cpu->sched.lock);
    spin_rel(&thread->cpu_lock, state);
    preempt_unlock(pstate);
    return wake;
}

bool sched_interrupt(thread_t *thread) {
    // see comment in sched_wake
    preempt_state_t pstate = preempt_lock();
    irq_state_t state = spin_acq(&thread->cpu_lock);

    cpu_t *cpu = thread->cpu;
    spin_acq_noirq(&cpu->sched.lock);

    bool wake = thread->state == THREAD_BLOCKED_INTERRUPTIBLE;

    if (wake) {
        do_wake(cpu, thread, EINTR);
    }

    spin_rel_noirq(&cpu->sched.lock);
    spin_rel(&thread->cpu_lock, state);
    preempt_unlock(pstate);
    return wake;
}

void sched_prepare_wait(bool interruptible) {
    irq_state_t state = save_disable_irq();

    cpu_t *cpu = get_current_cpu();
    spin_acq_noirq(&cpu->sched.lock);

    thread_t *thread = cpu->sched.current;
    ASSERT(thread->state == THREAD_RUNNING && thread != &cpu->sched.idle_thread);
    thread->state = interruptible ? THREAD_BLOCKED_INTERRUPTIBLE : THREAD_BLOCKED;

    spin_rel_noirq(&cpu->sched.lock);
    restore_irq(state);
}

int sched_perform_wait(uint64_t deadline) {
    preempt_state_t state = preempt_lock();
    ASSERT(state == PREEMPT_ENABLED);

    cpu_t *cpu = get_current_cpu();
    irq_state_t istate = spin_acq(&cpu->sched.lock);

    thread_t *thread = cpu->sched.current;

    if (thread->state == THREAD_BLOCKED || thread->state == THREAD_BLOCKED_INTERRUPTIBLE) {
        thread->timeout_event.deadline = deadline;

        if (deadline != 0) {
            timer_queue_event(&thread->timeout_event);
        }

        thread->wake_status = -1;
        do_yield(cpu, false);
        cpu = get_current_cpu();
    }

    spin_rel(&cpu->sched.lock, istate);
    preempt_unlock(state);

    ASSERT(thread->wake_status != -1);
    return thread->wake_status;
}

void sched_cancel_wait(void) {
    irq_state_t state = save_disable_irq();

    cpu_t *cpu = get_current_cpu();
    spin_acq_noirq(&cpu->sched.lock);

    thread_t *thread = cpu->sched.current;

    if (thread->state == THREAD_BLOCKED || thread->state == THREAD_BLOCKED_INTERRUPTIBLE) {
        thread->state = THREAD_RUNNING;
    }

    spin_rel_noirq(&cpu->sched.lock);
    restore_irq(state);
}

_Noreturn void sched_exit(void) {
    UNUSED preempt_state_t state = preempt_lock();
    ASSERT(state == PREEMPT_ENABLED);

    cpu_t *cpu = get_current_cpu();
    spin_acq(&cpu->sched.lock);

    thread_t *thread = cpu->sched.current;
    ASSERT(thread->state == THREAD_RUNNING);
    ASSERT(thread != &cpu->sched.idle_thread);

    thread->state = THREAD_EXITING;
    do_yield(cpu, false);
    UNREACHABLE();
}

void sched_migrate(struct cpu *dest) {
    preempt_state_t state = preempt_lock();
    ASSERT(state == PREEMPT_ENABLED);

    cpu_t *src = get_current_cpu();

    if (dest == src) {
        preempt_unlock(state);
        return;
    }

    thread_t *thread = src->sched.current;
    ASSERT(thread != &src->sched.idle_thread);
    ASSERT(thread->state == THREAD_RUNNING);

    irq_state_t istate = save_disable_irq();
    spin_acq_noirq(&thread->cpu_lock);

    if ((uintptr_t)src < (uintptr_t)dest) {
        spin_acq_noirq(&src->sched.lock);
        spin_acq_noirq(&dest->sched.lock);
    } else {
        spin_acq_noirq(&dest->sched.lock);
        spin_acq_noirq(&src->sched.lock);
    }

    thread->cpu = dest;

    enqueue(dest, thread);
    maybe_preempt(dest);

    // do_yield unlocks thread->cpu_lock to avoid the scenario where the destination
    // cpu has interrupts disabled while waiting on thread->cpu_lock
    do_yield(src, true);

    ASSERT(dest == get_current_cpu());
    spin_rel_noirq(&dest->sched.lock);
    restore_irq(istate);
    preempt_unlock(state);
}

_Noreturn void sched_init_thread(thread_t *prev, void (*func)(void *), void *ctx) {
    post_switch(prev);
    spin_rel_noirq(&get_current_cpu()->sched.lock);
    enable_irq();
    preempt_unlock(PREEMPT_ENABLED);
    func(ctx);
    sched_exit();
}

void thread_ref(thread_t *thread) {
    ref_inc(&thread->references);
}

void thread_deref(thread_t *thread) {
    if (ref_dec(&thread->references)) {
        if (thread->state == THREAD_CREATED) {
            reap_thread(thread);
        }

        ASSERT(thread->state == THREAD_EXITED);
        vfree(thread, sizeof(*thread));
    }
}

void sched_queue_task(task_t *task) {
    preempt_state_t state = preempt_lock();
    cpu_t *cpu = get_current_cpu();
    slist_insert_tail(&cpu->sched.tasks, &task->node);
    preempt_unlock(state);
}

_Noreturn void sched_idle(void) {
    cpu_t *cpu = get_current_cpu();
    ASSERT(current_thread == &cpu->sched.idle_thread);

    for (;;) {
        preempt_state_t state = preempt_lock();

        rcu_quiet(cpu);

        if (!preempt_unlock(state)) {
            cpu_idle();
        }
    }
}

// Migration is currently not implemented, so these are no-ops
migrate_state_t migrate_lock(void) {
    return false;
}

void migrate_unlock(migrate_state_t state) {
}

_Static_assert(KERNEL_STACK_SIZE >= KERNEL_STACK_ALIGN, "stack must be larger than its alignment");
_Static_assert(KERNEL_STACK_ALIGN <= PAGE_SIZE, "stack must not be aligned to multi-page boundary");

void *alloc_kernel_stack(void) {
    return vmalloc(KERNEL_STACK_SIZE);
}

void free_kernel_stack(void *stack) {
    vfree(stack, KERNEL_STACK_SIZE);
}
