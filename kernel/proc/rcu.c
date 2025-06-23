#include "proc/rcu.h"
#include "cpu/cpudata.h"
#include "cpu/cpumask.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "proc/event.h"
#include "proc/sched.h"
#include "util/slist.h"
#include "util/spinlock.h"

static cpu_mask_t rcu_cpu_states;
static cpu_mask_t rcu_cpus_enabled;

static spinlock_t rcu_lock;
static size_t rcu_generation;
static size_t rcu_max_generation;

static void run_callbacks(task_t *task) {
    rcu_cpu_state_t *state = &get_current_cpu()->rcu;
    state->task_queued = false;

    for (;;) {
        task_t *task = SLIST_REMOVE_HEAD(state->prev_cb, task_t, node);
        if (!task) break;
        task->func(task);
    }
}

static void rcu_init(void) {
    this_cpu_write(rcu.run_callbacks_task.func, run_callbacks);
}

INIT_DEFINE_EARLY(rcu, rcu_init, INIT_REFERENCE(scheduler_early));
INIT_DEFINE_EARLY_AP(rcu_ap, rcu_init, INIT_REFERENCE(scheduler_early_ap));

static void start_generation(size_t cur_gen) {
    //cpu_mask_fill(&rcu_cpu_states);
    cpu_mask_copy_atomic(&rcu_cpu_states, &rcu_cpus_enabled);

    cur_gen += 1;
    rcu_max_generation = cur_gen;

    if (cpu_mask_empty(&rcu_cpu_states)) cur_gen += 1;

    __atomic_store_n(&rcu_generation, cur_gen, __ATOMIC_RELEASE);
}

void rcu_quiet(cpu_t *cpu) {
    ASSERT(cpu == get_current_cpu());

    rcu_cpu_state_t *state = &cpu->rcu;
    size_t id = cpu->id;

    if (cpu_mask_get_atomic(&rcu_cpu_states, id)) {
        spin_acq_noirq(&rcu_lock);
        cpu_mask_set_notear(&rcu_cpu_states, id, false);

        if (cpu_mask_empty(&rcu_cpu_states)) {
            size_t gen = rcu_generation + 1;

            if (gen <= rcu_max_generation) {
                start_generation(gen);
            } else {
                __atomic_store_n(&rcu_generation, gen, __ATOMIC_RELEASE);
            }
        }

        spin_rel_noirq(&rcu_lock);
    }

    if (!slist_empty(&state->cur_cb) && __atomic_load_n(&rcu_generation, __ATOMIC_ACQUIRE) > state->generation) {
        slist_append_end(&state->prev_cb, &state->cur_cb);

        if (!state->task_queued) {
            state->task_queued = true;
            sched_queue_task(&state->run_callbacks_task);
        }
    }

    if (!slist_empty(&state->next_cb)) {
        slist_append_end(&state->cur_cb, &state->next_cb);
        spin_acq_noirq(&rcu_lock);

        state->generation = rcu_generation + 1;

        if (!cpu_mask_empty(&rcu_cpu_states)) {
            ASSERT(rcu_max_generation <= state->generation + 1);
            rcu_max_generation = state->generation + 1;
        } else {
            start_generation(rcu_generation);
        }

        spin_rel_noirq(&rcu_lock);
    }
}

void rcu_disable(void) {
    preempt_lock();
    cpu_t *cpu = get_current_cpu();
    cpu_mask_set_atomic(&rcu_cpus_enabled, cpu->id, false, __ATOMIC_ACQ_REL);
    rcu_quiet(cpu);
    preempt_unlock();
}

void rcu_enable(void) {
    preempt_lock();
    cpu_t *cpu = get_current_cpu();
    cpu_mask_set_atomic(&rcu_cpus_enabled, cpu->id, true, __ATOMIC_ACQ_REL);
    rcu_quiet(cpu);
    preempt_unlock();
}

void rcu_call(task_t *task) {
    preempt_lock();
    slist_insert_tail(&get_current_cpu()->rcu.next_cb, &task->node);
    preempt_unlock();
}

typedef struct {
    task_t base;
    event_t event;
} rcu_task_t;

static void do_event_signal(task_t *ptr) {
    rcu_task_t *self = (rcu_task_t *)ptr;
    event_signal(&self->event);
}

void rcu_sync(void) {
    rcu_task_t task = {.base.func = do_event_signal};
    rcu_call(&task.base);
    event_wait(&task.event, 0, false);
}
