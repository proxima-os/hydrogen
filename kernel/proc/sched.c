#include "proc/sched.h"
#include "arch/irq.h"
#include "cpu/cpudata.h"
#include "cpu/smp.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "string.h"
#include "util/list.h"
#include "util/refcount.h"
#include "util/spinlock.h"

#define PREEMPT_ENABLED 0
#define PREEMPT_DISABLED 1

void sched_init(void) {
    cpu_t *cpu = get_current_cpu();
    sched_t *sched = &cpu->sched;
    sched->current = &sched->idle_thread;
    sched->current->references = REF_INIT(2); // one for sched->idle_thread, one for sched->current
    sched->current->cpu = cpu;
    sched->current->state = THREAD_RUNNING;
}

int sched_create_thread(thread_t *thread, void (*func)(void *), void *ctx, void *stack, size_t stack_size) {
    memset(thread, 0, sizeof(*thread));

    int error = arch_init_thread(&thread->arch, func, ctx, stack, stack_size);
    if (unlikely(error)) return error;

    thread->references = REF_INIT(1);
    thread->cpu = get_current_cpu(); // TODO
    thread->state = THREAD_CREATED;

    return 0;
}

static void reap_thread(thread_t *thread) {
    // TODO
    thread->state = THREAD_EXITED;
}

static void post_switch(thread_t *prev) {
    if (prev->state == THREAD_EXITING) {
        // TODO: Use a separate reaper thread
        reap_thread(prev);
        thread_deref(prev);
    }
}

static void enqueue(cpu_t *cpu, thread_t *thread) {
    ASSERT(cpu == thread->cpu);

    list_insert_tail(&cpu->sched.queue, &thread->queue_node);
}

static thread_t *dequeue(cpu_t *cpu) {
    return LIST_REMOVE_HEAD(cpu->sched.queue, thread_t, queue_node);
}

static void do_yield(cpu_t *cpu) {
    ASSERT(cpu == get_current_cpu());

    thread_t *prev = cpu->sched.current;
    if (prev->state == THREAD_RUNNING && prev != &cpu->sched.idle_thread) enqueue(cpu, prev);

    thread_t *next = dequeue(cpu);
    if (!next) next = &cpu->sched.idle_thread;

    if (prev == next) return;

    cpu->sched.current = next;
    post_switch(CONTAINER(thread_t, arch, arch_switch_thread(&prev->arch, &next->arch)));
}

static void queue_yield(cpu_t *cpu) {
    ASSERT(cpu == get_current_cpu());
    ASSERT(this_cpu_read_tl(sched.preempt_state) == PREEMPT_DISABLED);
    cpu->sched.preempt_queued = true;
}

preempt_state_t preempt_lock(void) {
    preempt_state_t state = this_cpu_read_tl(sched.preempt_state);
    // can't use _tl for the write here, since that is allowed to use torn writes
    this_cpu_write(sched.preempt_state, PREEMPT_DISABLED);
    return state;
}

void preempt_unlock(preempt_state_t state) {
    if (state == PREEMPT_ENABLED) {
        // preemption is disabled, so we don't need to worry about migration
        cpu_t *cpu = get_current_cpu();

        task_t *task = cpu->sched.task_head;

        while (task) {
            cpu->sched.task_head = task->next;
            task->func(task);
            task = cpu->sched.task_head;
        }

        spin_acq_noirq(&cpu->sched.lock);

        if (cpu->sched.preempt_queued) {
            cpu->sched.preempt_queued = false;
            do_yield(cpu);
            cpu = get_current_cpu();
        }

        spin_rel_noirq(&cpu->sched.lock);
        __atomic_store_n(&cpu->sched.preempt_state, state, __ATOMIC_RELAXED); // avoid torn writes by using atmoics
    }
}

void sched_yield(void) {
    preempt_state_t state = preempt_lock();
    ASSERT(state == PREEMPT_ENABLED);

    cpu_t *cpu = get_current_cpu();
    spin_acq_noirq(&cpu->sched.lock);

    ASSERT(cpu->sched.current->state == THREAD_RUNNING);
    do_yield(cpu);
    cpu = get_current_cpu();

    spin_rel_noirq(&cpu->sched.lock);
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
    ASSERT(thread->state == THREAD_BLOCKED || thread->state == THREAD_BLOCKED_INTERRUPTIBLE);

    thread->state = THREAD_RUNNING;
    thread->wake_status = status;
    enqueue(cpu, thread);
    maybe_preempt(cpu);
}

bool sched_wake(thread_t *thread) {
    // need both preempt and irq lock here because sched_wake and sched_interrupt
    // are allowed to be called from irq context
    preempt_state_t pstate = preempt_lock();
    irq_state_t state = spin_acq(&thread->cpu_lock);

    cpu_t *cpu = thread->cpu;
    spin_acq_noirq(&cpu->sched.lock);

    if (thread->state == THREAD_CREATED) {
        thread->state = THREAD_BLOCKED;
        thread_ref(thread);
    }

    bool wake = thread->state == THREAD_BLOCKED || thread->state == THREAD_BLOCKED_INTERRUPTIBLE;

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
    preempt_state_t state = preempt_lock();

    cpu_t *cpu = get_current_cpu();
    spin_acq_noirq(&cpu->sched.lock);

    thread_t *thread = cpu->sched.current;
    ASSERT(thread->state == THREAD_RUNNING && thread != &cpu->sched.idle_thread);
    thread->state = interruptible ? THREAD_BLOCKED_INTERRUPTIBLE : THREAD_BLOCKED;

    spin_rel_noirq(&cpu->sched.lock);
    preempt_unlock(state);
}

int sched_perform_wait(void) {
    preempt_state_t state = preempt_lock();
    ASSERT(state == PREEMPT_ENABLED);

    cpu_t *cpu = get_current_cpu();
    spin_acq_noirq(&cpu->sched.lock);

    thread_t *thread = cpu->sched.current;
    ASSERT(thread->state == THREAD_BLOCKED || thread->state == THREAD_BLOCKED_INTERRUPTIBLE);

    thread->wake_status = -1;
    do_yield(cpu);
    cpu = get_current_cpu();

    spin_rel_noirq(&cpu->sched.lock);
    preempt_unlock(state);

    ASSERT(thread->wake_status != -1);
    return thread->wake_status;
}

void sched_cancel_wait(void) {
    preempt_state_t state = preempt_lock();

    cpu_t *cpu = get_current_cpu();
    spin_acq_noirq(&cpu->sched.lock);

    thread_t *thread = cpu->sched.current;
    ASSERT(thread->state == THREAD_BLOCKED || thread->state == THREAD_BLOCKED_INTERRUPTIBLE);
    thread->state = THREAD_RUNNING;

    spin_rel_noirq(&cpu->sched.lock);
    preempt_unlock(state);
}

_Noreturn void sched_exit(void) {
    preempt_state_t state = preempt_lock();
    ASSERT(state == PREEMPT_ENABLED);

    cpu_t *cpu = get_current_cpu();
    spin_acq_noirq(&cpu->sched.lock);

    thread_t *thread = cpu->sched.current;
    ASSERT(thread->state == THREAD_RUNNING);
    ASSERT(thread != &cpu->sched.idle_thread);

    thread->state = THREAD_EXITING;
    do_yield(cpu);
    UNREACHABLE();
}

_Noreturn void sched_init_thread(arch_thread_t *prev, void (*func)(void *), void *ctx) {
    post_switch(CONTAINER(thread_t, arch, prev));
    spin_rel_noirq(&get_current_cpu()->sched.lock);
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
        // TODO
    }
}

void queue_task(task_t *task) {
    task->next = NULL;

    preempt_state_t state = preempt_lock();
    cpu_t *cpu = get_current_cpu();

    if (cpu->sched.task_head) cpu->sched.task_tail->next = task;
    else cpu->sched.task_head = task;
    cpu->sched.task_tail = task;

    preempt_unlock(state);
}
