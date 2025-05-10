#include "proc/sched.h"
#include "arch/idle.h"
#include "arch/irq.h"
#include "arch/pmap.h" /* IWYU pragma: keep */
#include "arch/stack.h"
#include "arch/time.h"
#include "cpu/cpudata.h"
#include "cpu/smp.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/kvmm.h" /* IWYU pragma: keep */
#include "mem/pmap.h"
#include "mem/pmem.h" /* IWYU pragma: keep */
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/mutex.h"
#include "proc/process.h"
#include "proc/rcu.h"
#include "proc/signal.h"
#include "sections.h"
#include "string.h"
#include "util/handle.h"
#include "util/list.h"
#include "util/object.h"
#include "util/panic.h"
#include "util/slist.h"
#include "util/spinlock.h"
#include "util/time.h"
#include <stdbool.h>
#include <stdint.h>

#define PREEMPT_ENABLED 0
#define PREEMPT_DISABLED 1

static void handle_timeout_event(timer_event_t *self);

static void reap_thread(thread_t *thread) {
    __atomic_fetch_sub(&thread->cpu->sched.num_threads, 1, __ATOMIC_RELAXED);

    arch_reap_thread(&thread->arch);
    free_kernel_stack(thread->stack);
    if (thread->vmm) obj_deref(&thread->vmm->base);

    if (thread->process) proc_thread_exit(thread->process, thread);
    if (thread->namespace) obj_deref(&thread->namespace->base);

    thread->state = THREAD_EXITED;
}

static void thread_free(object_t *ptr) {
    thread_t *thread = (thread_t *)ptr;

    if (thread->state == THREAD_CREATED) {
        reap_thread(thread);
    }

    ASSERT(thread->state == THREAD_EXITED);

    if (thread->pid) {
        pid_t *pid = thread->pid;
        mutex_acq(&pid->remove_lock, 0, false);
        rcu_write(pid->thread, NULL);
        pid_handle_removal_and_unlock(pid);
    }

    if (thread->process) obj_deref(&thread->process->base);

    signal_cleanup(&thread->sig_target);
    vfree(thread, sizeof(*thread));
}

static const object_ops_t thread_ops = {.free = thread_free};

INIT_TEXT void sched_init(void) {
    cpu_t *cpu = get_current_cpu();
    sched_t *sched = &cpu->sched;
    sched->current = &sched->idle_thread;
    sched->current->base.ops = &thread_ops;
    obj_init(&sched->current->base, OBJECT_THREAD);
    obj_ref(&sched->current->base); // for sched->current
    sched->current->cpu = cpu;
    sched->current->state = THREAD_RUNNING;
    sched->current->process = &kernel_process;
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
        obj_deref(&thread->base);
    }
}

INIT_TEXT void sched_init_late(void) {
    cpu_t *cpu = get_current_cpu();

    cpu->sched.idle_thread.process = &kernel_process;
    obj_ref(&kernel_process.base);
    proc_thread_create(&kernel_process, &cpu->sched.idle_thread);

    int error = sched_create_thread(&cpu->sched.reaper, reaper_func, NULL, cpu, &kernel_process, 0);
    if (unlikely(error)) panic("sched: failed to create reaper thread (%e)", error);
}

int sched_create_thread(
        thread_t **out,
        void (*func)(void *),
        void *ctx,
        cpu_t *cpu,
        struct process *process,
        unsigned flags
) {
    thread_t *thread = vmalloc(sizeof(*thread));
    if (unlikely(!thread)) return ENOMEM;
    memset(thread, 0, sizeof(*thread));

    thread->stack = alloc_kernel_stack();
    if (unlikely(!thread->stack)) {
        vfree(thread, sizeof(*thread));
        return ENOMEM;
    }

    int error = arch_init_thread(&thread->arch, func, ctx, thread->stack, flags);
    if (unlikely(error)) {
        free_kernel_stack(thread->stack);
        vfree(thread, sizeof(*thread));
        return error;
    }

    thread->base.ops = &thread_ops;
    obj_init(&thread->base, OBJECT_THREAD);
    thread->cpu = cpu;
    thread->state = THREAD_CREATED;
    thread->timeout_event.func = handle_timeout_event;
    thread->user_thread = (flags & THREAD_USER) != 0;
    thread->sig_mask = current_thread->sig_mask;
    thread->sig_stack.__flags = __SS_DISABLE;

    if (process != NULL) {
        thread->process = process;
        int error = proc_thread_create(process, thread);

        if (unlikely(error)) {
            arch_reap_thread(&thread->arch);
            free_kernel_stack(thread->stack);
            vfree(thread, sizeof(*thread));
            return error;
        }

        obj_ref(&process->base);
    }

    if (thread->cpu == NULL) {
        size_t cur_count = SIZE_MAX;

        SLIST_FOREACH(cpus, cpu_t, node, cpu) {
            size_t count = __atomic_load_n(&cpu->sched.num_threads, __ATOMIC_RELAXED);

            if (count < cur_count) {
                thread->cpu = cpu;
                cur_count = count;
            }
        }

        ASSERT(thread->cpu != NULL);
    }

    __atomic_fetch_add(&thread->cpu->sched.num_threads, 1, __ATOMIC_RELAXED);

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

    thread_t *current = cpu->sched.current;
    if (current->vmm) pmap_switch(&current->vmm->pmap);
}

static void enqueue(cpu_t *cpu, thread_t *thread) {
    ASSERT(cpu == thread->cpu);

    list_insert_tail(&cpu->sched.queue, &thread->queue_node);
}

static thread_t *dequeue(cpu_t *cpu) {
    return LIST_REMOVE_HEAD(cpu->sched.queue, thread_t, queue_node);
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
    // don't need atomics here, interrupts are currently disabled
    cpu->sched.preempt_queued = true;
    cpu->sched.preempt_work = true;
}

preempt_state_t preempt_lock(void) {
    preempt_state_t state = this_cpu_read(sched.preempt_state);
    this_cpu_write(sched.preempt_state, PREEMPT_DISABLED);
    return state;
}

void preempt_unlock(preempt_state_t state) {
    if (state != PREEMPT_ENABLED) return;

    this_cpu_write(sched.preempt_state, state);
    if (likely(!this_cpu_read(sched.preempt_work))) return;

    do {
        this_cpu_write(sched.preempt_state, PREEMPT_DISABLED);

        // preemption is disabled, so we don't need to worry about migration
        cpu_t *cpu = get_current_cpu();
        __atomic_store_n(&cpu->sched.preempt_work, false, __ATOMIC_RELAXED);

        for (;;) {
            irq_state_t state = save_disable_irq();
            task_t *task = SLIST_REMOVE_HEAD(cpu->sched.tasks, task_t, node);
            restore_irq(state);
            if (!task) break;
            task->func(task);
        }

        if (__atomic_load_n(&cpu->sched.preempt_queued, __ATOMIC_RELAXED)) {
            irq_state_t state = spin_acq(&cpu->sched.lock);
            cpu->sched.preempt_queued = false;
            do_yield(cpu, false);
            cpu = get_current_cpu();
            spin_rel(&cpu->sched.lock, state);
        }

        this_cpu_write(sched.preempt_state, state);
    } while (unlikely(this_cpu_read(sched.preempt_work)));
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

    if (thread->state == THREAD_CREATED) obj_ref(&thread->base);

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

bool sched_interrupt(thread_t *thread, bool force_user_transition) {
    // see comment in sched_wake
    preempt_state_t pstate = preempt_lock();
    irq_state_t state = spin_acq(&thread->cpu_lock);

    cpu_t *cpu = thread->cpu;
    spin_acq_noirq(&cpu->sched.lock);

    bool wake = thread->state == THREAD_BLOCKED_INTERRUPTIBLE;

    if (wake) {
        do_wake(cpu, thread, EINTR);
    } else if (force_user_transition && thread->user_thread && cpu != get_current_cpu()) {
        smp_trigger_user_transition(cpu);
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

    __atomic_fetch_sub(&src->sched.num_threads, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&dest->sched.num_threads, 1, __ATOMIC_RELAXED);

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

void sched_queue_task(task_t *task) {
    irq_state_t state = save_disable_irq();
    cpu_t *cpu = get_current_cpu();
    slist_insert_tail(&cpu->sched.tasks, &task->node);
    __atomic_store_n(&cpu->sched.preempt_work, true, __ATOMIC_RELAXED);
    restore_irq(state);
}

#define RCU_QUIET_INTERVAL (1 * NS_PER_MS)

typedef struct {
    task_t base;
    timer_event_t event;
} rcu_quiet_task_t;

static void queued_rcu_quiet(task_t *ptr) {
    rcu_quiet(get_current_cpu());

    rcu_quiet_task_t *self = (rcu_quiet_task_t *)ptr;
    self->event.deadline = arch_read_time() + RCU_QUIET_INTERVAL;
    timer_queue_event(&self->event);
}

static void queue_rcu_quiet(timer_event_t *ptr) {
    rcu_quiet_task_t *self = CONTAINER(rcu_quiet_task_t, event, ptr);
    sched_queue_task(&self->base);
}

_Noreturn void sched_idle(void) {
    UNUSED cpu_t *cpu = get_current_cpu();
    ASSERT(current_thread == &cpu->sched.idle_thread);

    // Without this, fully idle CPUs break RCU.
    rcu_quiet_task_t task = {
            .base.func = queued_rcu_quiet,
            .event.deadline = arch_read_time() + RCU_QUIET_INTERVAL,
            .event.func = queue_rcu_quiet,
    };
    timer_queue_event(&task.event);

    for (;;) {
        cpu_idle();
    }
}

// Migration is currently not implemented, so these are no-ops
migrate_state_t migrate_lock(void) {
    return false;
}

void migrate_unlock(migrate_state_t state) {
}

_Static_assert((KERNEL_STACK_SIZE & PAGE_MASK) == 0, "stack size must be a multiple of the page size");
_Static_assert(KERNEL_STACK_SIZE >= KERNEL_STACK_ALIGN, "stack must be larger than its alignment");
_Static_assert(KERNEL_STACK_ALIGN <= PAGE_SIZE, "stack must not be aligned to multi-page boundary");

void *alloc_kernel_stack(void) {
#if HYDROGEN_ASSERTIONS
    uintptr_t addr = kvmm_alloc(KERNEL_STACK_SIZE + PAGE_SIZE);
    if (unlikely(!addr)) return NULL;

    if (unlikely(!pmem_reserve(KERNEL_STACK_SIZE >> PAGE_SHIFT))) {
        kvmm_free(addr, KERNEL_STACK_SIZE + PAGE_SIZE);
    }

    if (unlikely(!pmap_prepare(NULL, addr + PAGE_SIZE, KERNEL_STACK_SIZE))) {
        pmem_unreserve(KERNEL_STACK_SIZE >> PAGE_SHIFT);
        kvmm_free(addr, KERNEL_STACK_SIZE + PAGE_SIZE);
    }

    pmap_alloc(NULL, addr + PAGE_SIZE, KERNEL_STACK_SIZE, PMAP_READABLE | PMAP_WRITABLE);
    return (void *)(addr + PAGE_SIZE);
#else
    return vmalloc(KERNEL_STACK_SIZE);
#endif
}

void free_kernel_stack(void *stack) {
#if HYDROGEN_ASSERTIONS
    pmap_unmap(NULL, (uintptr_t)stack, KERNEL_STACK_SIZE);
    pmem_unreserve(KERNEL_STACK_SIZE >> PAGE_SHIFT);
    kvmm_free((uintptr_t)stack - PAGE_SIZE, KERNEL_STACK_SIZE + PAGE_SIZE);
#else
    vfree(stack, KERNEL_STACK_SIZE);
#endif
}
