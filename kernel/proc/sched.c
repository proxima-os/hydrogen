#include "proc/sched.h"
#include "arch/idle.h"
#include "arch/irq.h"
#include "arch/pmap.h" /* IWYU pragma: keep */
#include "arch/stack.h"
#include "arch/time.h"
#include "cpu/cpudata.h"
#include "cpu/cpumask.h"
#include "cpu/smp.h"
#include "errno.h"
#include "init/task.h"
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

#define PREEMPT_NO_WORK (1u << 31)

#define NORMAL_PRIORITIES (SCHED_PRIORITIES - SCHED_RT_PRIORITIES)

#define TIMESLICE_MIN (10 * NS_PER_MS) // The time slice (in nanoseconds) used for priorities < SCHED_RT_PRIORITIES
#define TIMESLICE_MAX (50 * NS_PER_MS) // The time slice (in nanoseconds) used for priority SCHED_PRIORITIES
// The number of nanoseconds to increase the time slice by when moving down a queue.
// Only valid if the new queue >= SCHED_RT_PRIORITIES
#define TIMESLICE_INC ((TIMESLICE_MAX - TIMESLICE_MIN + (NORMAL_PRIORITIES / 2)) / NORMAL_PRIORITIES)

// Every so often, the scheduler increases the priority of all non-real-time tasks by one to prevent starvation.
// This parameter determines how often that happens.
#define BOOST_INTERVAL_NS NS_PER_SEC

static void handle_timeout_event(timer_event_t *self);

static void reap_thread(thread_t *thread) {
    __atomic_fetch_sub(&thread->cpu->sched.num_threads, 1, __ATOMIC_RELAXED);

    arch_reap_thread(&thread->arch);
    free_kernel_stack(thread->stack);
    if (thread->vmm) obj_deref(&thread->vmm->base);

    if (thread->process) proc_thread_exit(thread->process, thread, thread->exit_status);

    // Note: the namespace deference MUST be done during reaping, not during thread free!
    // Otherwise, you have a potential for permanent reference cycles:
    // - Thread A creates namespace A
    // - Thread A creates thread B in namespace A
    // - Thread A closes its handle to namespace A - its only reference is now thread B's implicit reference
    // - Thread B creates thread C using HYDROGEN_THIS_NAMESPACE
    // - Thread B exits without closing the handle to thread C
    // - Thread C exits immediately
    // If namespace dereferencing is moved to be done during thread freeing, this scenario results in a permanent
    // reference cycle: namespace A holds a reference to thread C because it contains a handle to it, thread C holds a
    // reference to namespace A because it exists, and there are no other references to namespace A or thread C in the
    // system.
    if (thread->namespace) obj_deref(&thread->namespace->base);

    thread->state = THREAD_EXITED;
}

static void thread_free(object_t *ptr) {
    thread_t *thread = (thread_t *)ptr;

    if (thread->pid) {
        pid_t *pid = thread->pid;
        mutex_acq(&pids_lock, 0, false);

        if (__atomic_load_n(&thread->base.references.references, __ATOMIC_ACQUIRE) != 0) {
            mutex_rel(&pids_lock);
            return;
        }

        pid->thread = NULL;
        pid_handle_removal_and_unlock(pid);
    }

    if (thread->state == THREAD_CREATED) {
        reap_thread(thread);
    }

    ASSERT(thread->state == THREAD_EXITED);

    if (thread->process) obj_deref(&thread->process->base);

    signal_cleanup(&thread->sig_target);
    vfree(thread, sizeof(*thread));
}

static const object_ops_t thread_ops = {
    .free = thread_free,
};

static void handle_timeslice_event(timer_event_t *event);
static void maybe_preempt(cpu_t *cpu);

static void update_cur_queue(cpu_t *cpu) {
    cpu->sched.cur_queue = __builtin_ffsll(cpu->sched.queue_mask) - 1;
}

static void handle_boost_event(timer_event_t *event) {
    event->deadline += BOOST_INTERVAL_NS;
    timer_queue_event(event);

    cpu_t *cpu = get_current_cpu();
    uint64_t mask = cpu->sched.queue_mask >> (SCHED_RT_PRIORITIES + 1);
    uint64_t cmask = 1ull << (SCHED_RT_PRIORITIES + 1);
    list_t *queue = &cpu->sched.queues[SCHED_RT_PRIORITIES + 1];

    while (mask != 0) {
        size_t extra = __builtin_ctzll(mask);
        mask >>= extra;
        cmask <<= extra;
        queue += extra;

        LIST_FOREACH(*queue, thread_t, queue_node, thread) {
            thread->queue -= 1;
            thread->timeslice_tot -= TIMESLICE_INC;
        }

        list_append_end(queue - 1, queue);
        cpu->sched.queue_mask |= cmask >> 1;
        cpu->sched.queue_mask &= ~cmask;

        mask &= ~1ull;
    }

    update_cur_queue(cpu);
    maybe_preempt(cpu);
}

static void sched_init(void) {
    cpu_t *cpu = get_current_cpu();
    sched_t *sched = &cpu->sched;
    sched->cur_queue = -1;
    sched->preempt_level = PREEMPT_NO_WORK;
    sched->timeslice_event.func = handle_timeslice_event;
    sched->boost_event.func = handle_boost_event;
    sched->current = &sched->idle_thread;
    sched->current->base.ops = &thread_ops;
    obj_init(&sched->current->base, OBJECT_THREAD);
    obj_ref(&sched->current->base); // for sched->current
    sched->current->queue = -1;
    sched->current->cpu = cpu;
    sched->current->state = THREAD_RUNNING;
    sched->current->process = &kernel_process;
    cpu_mask_fill(&sched->current->affinity);
}

INIT_DEFINE_EARLY(scheduler_early, sched_init);
INIT_DEFINE_EARLY_AP(scheduler_early_ap, sched_init);

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

static void sched_init_late(void) {
    cpu_t *cpu = get_current_cpu();

    cpu->sched.idle_thread.process = &kernel_process;
    obj_ref(&kernel_process.base);
    proc_thread_create(&kernel_process, &cpu->sched.idle_thread);

    int error = sched_create_thread(&cpu->sched.reaper, reaper_func, NULL, cpu, &kernel_process, 0);
    if (unlikely(error)) panic("sched: failed to create reaper thread (%e)", error);

    cpu->sched.boost_event.deadline = arch_read_time() + BOOST_INTERVAL_NS;
    timer_queue_event(&cpu->sched.boost_event);
}

INIT_DEFINE(scheduler, sched_init_late);
INIT_DEFINE_AP(scheduler_ap, sched_init_late);

static cpu_t *select_cpu_for_affinity(const cpu_mask_t *affinity) {
    cpu_t *cur = NULL;
    size_t cur_count = SIZE_MAX;

    SLIST_FOREACH(cpus, cpu_t, node, cpu) {
        if (!cpu_mask_get_atomic(affinity, cpu->id)) continue;

        size_t count = __atomic_load_n(&cpu->sched.num_threads, __ATOMIC_RELAXED);

        if (count < cur_count) {
            cur = cpu;
            cur_count = count;
        }
    }

    ASSERT(cur != NULL);
    return cur;
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
    thread->affinity = current_thread->affinity;

    if (current_thread->queue >= 0) {
        thread->queue = current_thread->queue;
        thread->timeslice_tot = current_thread->timeslice_tot;
    } else {
        thread->queue = SCHED_RT_PRIORITIES;
        thread->timeslice_tot = TIMESLICE_MIN + TIMESLICE_INC;
    }

    thread->timeslice_rem = thread->timeslice_tot;

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

    if (thread->cpu == NULL) thread->cpu = select_cpu_for_affinity(&thread->affinity);

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

    int queue_idx = thread->queue;
    if (queue_idx < 0) return;

    list_t *queue = &cpu->sched.queues[queue_idx];
    list_insert_tail(queue, &thread->queue_node);
    cpu->sched.queue_mask |= 1ull << queue_idx;
    if (cpu->sched.cur_queue < 0 || queue_idx < cpu->sched.cur_queue) cpu->sched.cur_queue = queue_idx;
}

static thread_t *dequeue(cpu_t *cpu) {
    int queue_idx = cpu->sched.cur_queue;
    if (queue_idx < 0) return NULL;

    list_t *queue = &cpu->sched.queues[queue_idx];
    thread_t *thread = LIST_REMOVE_HEAD(*queue, thread_t, queue_node);
    ASSERT(thread != NULL);

    if (list_empty(queue)) {
        cpu->sched.queue_mask &= ~(1ull << queue_idx);
        update_cur_queue(cpu);
    }

    return thread;
}

static void time_account_submit(thread_t *thread, uint64_t time) {
    process_t *process = thread->process;
    uint64_t tot_time = time - thread->account_start_time;
    uint64_t kern_time = time - thread->kernel_start_time;
    uint64_t user_time = tot_time - kern_time;

    __atomic_fetch_add(&process->kern_time, kern_time, __ATOMIC_RELAXED);
    __atomic_fetch_add(&process->user_time, user_time, __ATOMIC_RELAXED);
    thread->kern_time += kern_time;
    thread->user_time += user_time;
}

static void do_yield(cpu_t *cpu, bool migrating) {
    ASSERT(cpu == get_current_cpu());

    rcu_quiet(cpu);

    thread_t *prev = cpu->sched.current;
    if (!migrating && prev->state == THREAD_RUNNING) enqueue(cpu, prev);

    thread_t *next = dequeue(cpu);
    if (!next) next = &cpu->sched.idle_thread;

    uint64_t time = arch_read_time();
    uint64_t delta = time - cpu->sched.timeslice_start_time;
    cpu->sched.timeslice_start_time = time;

    if (delta >= prev->timeslice_rem) {
        prev->timeslice_rem = prev->timeslice_tot;
    }

    timer_cancel_event(&cpu->sched.timeslice_event);

    if (next->timeslice_rem) {
        cpu->sched.timeslice_event.deadline = time + next->timeslice_rem;
        timer_queue_event(&cpu->sched.timeslice_event);
    }

    if (prev == next) return;

    cpu->sched.current = next;

    prev->active = false;
    next->active = true;

    time_account_submit(prev, time);
    next->account_start_time = next->kernel_start_time = time;

    post_switch(arch_switch_thread(prev, next));
}

static void queue_yield(cpu_t *cpu) {
    ASSERT(cpu == get_current_cpu());
    ASSERT(cpu->sched.preempt_level & ~PREEMPT_NO_WORK);
    // don't need atomics here, interrupts are currently disabled
    cpu->sched.preempt_level &= ~PREEMPT_NO_WORK;
    cpu->sched.preempt_queued = true;
}

static void handle_timeslice_event(timer_event_t *event) {
    cpu_t *cpu = get_current_cpu();
    thread_t *thread = cpu->sched.current;

    ASSERT(thread->timeslice_tot != 0);

    if (thread->queue >= SCHED_RT_PRIORITIES && thread->queue < (SCHED_PRIORITIES - 1)) {
        thread->queue += 1;
        thread->timeslice_tot += TIMESLICE_INC;
    }

    queue_yield(cpu);
}

void preempt_lock(void) {
    this_cpu_inc32(sched.preempt_level);
}

static void do_preempt_work(void) {
    for (;;) {
        preempt_lock();

        // preemption is disabled, so we don't need to worry about migration
        cpu_t *cpu = get_current_cpu();
        __atomic_store_n(&cpu->sched.preempt_level, cpu->sched.preempt_level | PREEMPT_NO_WORK, __ATOMIC_RELAXED);

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

        if (likely(!this_cpu_dec32(sched.preempt_level))) return;
    }
}

void preempt_unlock(void) {
    if (unlikely(this_cpu_dec32(sched.preempt_level))) do_preempt_work();
}

#define ASSERT_WAS_PREEMPT() ASSERT((this_cpu_read(sched.preempt_level) & ~PREEMPT_NO_WORK) == 1)

void sched_yield(void) {
    preempt_lock();
    ASSERT_WAS_PREEMPT();

    cpu_t *cpu = get_current_cpu();
    irq_state_t istate = spin_acq(&cpu->sched.lock);

    ASSERT(cpu->sched.current->state == THREAD_RUNNING);
    do_yield(cpu, false);
    cpu = get_current_cpu();

    spin_rel(&cpu->sched.lock, istate);
    preempt_unlock();
}

static bool should_preempt(cpu_t *cpu) {
    if (cpu->sched.cur_queue < 0) return false;
    return cpu->sched.current->queue < 0 || cpu->sched.cur_queue < cpu->sched.current->queue;
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
    ASSERT(
        thread->state == THREAD_CREATED || thread->state == THREAD_BLOCKED ||
        thread->state == THREAD_BLOCKED_INTERRUPTIBLE
    );

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
    preempt_lock();
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
    preempt_unlock();
    return wake;
}

bool sched_interrupt(thread_t *thread, bool force_user_transition) {
    // see comment in sched_wake
    preempt_lock();
    irq_state_t state = spin_acq(&thread->cpu_lock);

    cpu_t *cpu = thread->cpu;
    spin_acq_noirq(&cpu->sched.lock);

    bool wake = thread->state == THREAD_BLOCKED_INTERRUPTIBLE;

    if (wake) {
        do_wake(cpu, thread, EINTR);
    } else {
        thread->interrupted = true;

        if (force_user_transition && thread->user_thread && cpu != get_current_cpu()) {
            smp_trigger_user_transition(cpu);
        }
    }

    spin_rel_noirq(&cpu->sched.lock);
    spin_rel(&thread->cpu_lock, state);
    preempt_unlock();
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
    preempt_lock();
    ASSERT_WAS_PREEMPT();

    cpu_t *cpu = get_current_cpu();
    irq_state_t istate = spin_acq(&cpu->sched.lock);

    thread_t *thread = cpu->sched.current;

    if (thread->state == THREAD_BLOCKED || thread->state == THREAD_BLOCKED_INTERRUPTIBLE) {
        if (thread->state == THREAD_BLOCKED_INTERRUPTIBLE && thread->interrupted) {
            thread->interrupted = false;
            thread->state = THREAD_RUNNING;
            thread->wake_status = EINTR;
        } else {
            thread->timeout_event.deadline = deadline;

            if (deadline != 0) {
                timer_queue_event(&thread->timeout_event);
            }

            thread->wake_status = -1;
            do_yield(cpu, false);
            cpu = get_current_cpu();
        }
    }

    spin_rel(&cpu->sched.lock, istate);
    preempt_unlock();

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

_Noreturn void sched_exit(int status) {
    preempt_lock();
    ASSERT_WAS_PREEMPT();

    cpu_t *cpu = get_current_cpu();
    spin_acq(&cpu->sched.lock);

    thread_t *thread = cpu->sched.current;
    ASSERT(thread->state == THREAD_RUNNING);
    ASSERT(thread != &cpu->sched.idle_thread);

    thread->state = THREAD_EXITING;
    thread->exit_status = status;

    do_yield(cpu, false);
    UNREACHABLE();
}

static void do_migrate(cpu_t *src, cpu_t *dest) {
    ASSERT(src == get_current_cpu());
    if (src == dest) return;

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
}

void sched_migrate(struct cpu *dest) {
    preempt_lock();
    ASSERT_WAS_PREEMPT();

    cpu_t *src = get_current_cpu();
    do_migrate(src, dest);

    preempt_unlock();
}

void sched_commit_time_accounting(void) {
    irq_state_t state = save_disable_irq();
    cpu_t *cpu = get_current_cpu();
    spin_acq_noirq(&cpu->sched.lock);

    thread_t *thread = cpu->sched.current;
    uint64_t time = arch_read_time();
    time_account_submit(thread, time);
    thread->account_start_time = thread->kernel_start_time = time;

    spin_rel_noirq(&cpu->sched.lock);
    restore_irq(state);
}

void sched_set_affinity(const cpu_mask_t *mask) {
    preempt_lock();
    ASSERT_WAS_PREEMPT();

    cpu_t *src = get_current_cpu();
    cpu_t *dest = src;

    if (!cpu_mask_get(mask, src->id)) {
        dest = select_cpu_for_affinity(mask);
    }

    current_thread->affinity = *mask;
    do_migrate(src, dest);

    preempt_unlock();
}

void sched_set_priority(int priority, bool timeslice) {
    ASSERT(priority >= 0);
    ASSERT(priority < SCHED_PRIORITIES);

    preempt_lock();

    cpu_t *cpu = get_current_cpu();
    irq_state_t state = spin_acq(&cpu->sched.lock);

    thread_t *thread = cpu->sched.current;
    bool update_time_slice = false;

    if (priority >= SCHED_RT_PRIORITIES) {
        if (thread->queue < SCHED_RT_PRIORITIES) {
            thread->queue = SCHED_RT_PRIORITIES;
            thread->timeslice_tot = TIMESLICE_MIN + TIMESLICE_INC;
            update_time_slice = true;
        }
    } else if (priority != thread->queue) {
        thread->queue = priority;

        if (timeslice) {
            if (!thread->timeslice_tot) {
                thread->timeslice_tot = TIMESLICE_MIN;
                update_time_slice = true;
            }
        } else if (thread->timeslice_tot) {
            thread->timeslice_tot = 0;
            update_time_slice = true;
        }
    }

    if (update_time_slice) {
        thread->timeslice_rem = thread->timeslice_tot;
        timer_cancel_event(&cpu->sched.timeslice_event);

        if (thread->timeslice_rem) {
            cpu->sched.timeslice_start_time = arch_read_time();
            cpu->sched.timeslice_event.deadline = cpu->sched.timeslice_start_time + thread->timeslice_rem;
            timer_queue_event(&cpu->sched.timeslice_event);
        }
    }

    maybe_preempt(cpu);

    spin_rel(&cpu->sched.lock, state);
    preempt_unlock();
}

int sched_get_priority(bool *timeslice_out) {
    preempt_lock();

    cpu_t *cpu = get_current_cpu();
    irq_state_t state = spin_acq(&cpu->sched.lock);

    int priority = cpu->sched.current->queue;
    *timeslice_out = cpu->sched.current->timeslice_tot;

    spin_rel(&cpu->sched.lock, state);
    preempt_unlock();
    return priority;
}

_Noreturn void sched_init_thread(thread_t *prev, void (*func)(void *), void *ctx) {
    post_switch(prev);
    spin_rel_noirq(&get_current_cpu()->sched.lock);
    enable_irq();
    ASSERT_WAS_PREEMPT();
    preempt_unlock();
    func(ctx);
    sched_exit(0);
}

void sched_queue_task(task_t *task) {
    irq_state_t state = save_disable_irq();
    cpu_t *cpu = get_current_cpu();
    slist_insert_tail(&cpu->sched.tasks, &task->node);
    cpu->sched.preempt_level &= ~PREEMPT_NO_WORK;
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
}

void free_kernel_stack(void *stack) {
    pmap_unmap(NULL, (uintptr_t)stack, KERNEL_STACK_SIZE);
    pmem_unreserve(KERNEL_STACK_SIZE >> PAGE_SHIFT);
    kvmm_free((uintptr_t)stack - PAGE_SIZE, KERNEL_STACK_SIZE + PAGE_SIZE);
}
