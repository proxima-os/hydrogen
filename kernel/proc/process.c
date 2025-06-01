#include "proc/process.h"
#include "arch/irq.h"
#include "arch/pmap.h"
#include "arch/time.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "fs/vfs.h"
#include "init/main.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "proc/mutex.h"
#include "proc/rcu.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "string.h"
#include "util/eventqueue.h"
#include "util/list.h"
#include "util/object.h"
#include "util/panic.h"
#include "util/refcount.h"
#include "util/spinlock.h"
#include "util/time.h"
#include <hydrogen/eventqueue.h>
#include <hydrogen/process.h>
#include <hydrogen/signal.h>
#include <hydrogen/types.h>
#include <stddef.h>
#include <stdint.h>

process_t kernel_process;
process_t *init_process;

typedef union {
    pid_t *allocated;
    struct {
        // For determining whether a given PID has been allocated, we rely on `limit` overlapping the upper 32 bits of
        // `allocated`. A valid value of `allocated` always has its highest bit set, as it is a kernel address, and a
        // valid value of `limit` never has its highest bit set, as the highest valid PID is INT32_MAX.
#if __SIZEOF_POINTER__ == 4 || __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        int32_t limit;
        int32_t next;
#else
        int32_t next;
        int32_t limit;
#endif
    } free;
} pid_table_entry_t;

static pid_table_entry_t *pid_table;
static int32_t free_pids = -1;
static size_t pids_capacity;
mutex_t pids_lock;

static pgroup_t kernel_group = {.references = REF_INIT(1)};
static session_t kernel_session = {.references = REF_INIT(1)};

static void init_pids(void) {
    pids_capacity = 8;
    pid_table = vmalloc(pids_capacity * sizeof(*pid_table));
    if (unlikely(!pid_table)) panic("failed to allocate pid table");
    memset(pid_table, 0, sizeof(*pid_table) * pids_capacity);

    pid_table[0].free.limit = pids_capacity - 1;
    pid_table[0].free.next = -1;
    free_pids = 0;
}

static int expand_pids(void) {
    ASSERT(pids_capacity != 0);

    size_t new_cap = pids_capacity * 2;
    if (new_cap > (size_t)INT32_MAX) new_cap = (size_t)INT32_MAX + 1;
    if (new_cap <= pids_capacity) return EAGAIN;

    pid_table_entry_t *new_table = vrealloc(
        pid_table,
        pids_capacity * sizeof(*pid_table),
        new_cap * sizeof(*pid_table)
    );
    if (unlikely(!new_table)) return ENOMEM;

    memset(&new_table[pids_capacity], 0, (new_cap - pids_capacity) * sizeof(*pid_table));

    new_table[pids_capacity].free.next = free_pids;
    new_table[pids_capacity].free.limit = new_cap - pids_capacity - 1;
    free_pids = pids_capacity;

    pid_table = new_table;
    pids_capacity = new_cap;

    return 0;
}

static void make_free_entry(int32_t pid, int32_t next, int32_t limit) {
    pid_table[pid].free.limit = limit;
    pid_table[pid].free.next = next;
}

static int allocate_pid(process_t *process, thread_t *thread) {
    ASSERT(process != NULL || thread != NULL);

    pid_t *pid = vmalloc(sizeof(*pid));
    if (unlikely(!pid)) return 0;
    memset(pid, 0, sizeof(*pid));

    if (process != NULL) {
        pid->process = process;
        process->pid = pid;
    }

    if (thread != NULL) {
        pid->thread = thread;
        thread->pid = pid;
    }

    if (free_pids < 0) {
        int error = expand_pids();
        if (unlikely(error)) return error;
    }

    int32_t id = free_pids;
    pid_table_entry_t *entry = &pid_table[id];

    if (entry->free.limit == 0) {
        free_pids = entry->free.next;
    } else {
        free_pids = id + 1;
        make_free_entry(free_pids, entry->free.next, entry->free.limit - 1);
    }

    pid->id = id;
    entry->allocated = pid;
    return 0;
}

static process_t *get_parent_with_locked_children(process_t *process);
static void reap_process(process_t *process, process_t *parent);

static void process_free(object_t *ptr) {
    process_t *process = (process_t *)ptr;

    do {
        ASSERT(process != &kernel_process);

        pid_t *pid = process->pid;
        mutex_acq(&pids_lock, 0, false);

        if (!ref_dec(&process->base.references)) {
            mutex_rel(&pids_lock);
            return;
        }

        pid->process = NULL;
        pid_handle_removal_and_unlock(pid);

        process_t *parent;

        if (!process->exit_signal_sent) {
            parent = get_parent_with_locked_children(process);
            reap_process(process, parent);
            mutex_rel(&parent->children_lock);
        } else {
            parent = NULL;
        }

        proc_alarm(process, 0);
        pgroup_deref(process->group);
        ident_deref(process->identity);

        signal_cleanup(&process->sig_target);
        event_source_cleanup(&process->status_event);
        vfree(process, sizeof(*process));

        if (parent != NULL) {
            obj_deref(&parent->base);

            if (ref_dec_maybe(&parent->base.references)) {
            process = parent;
            } else {
                process = NULL;
            }
        } else {
            process = NULL;
        }
    } while (process != NULL);
}

static int process_event_add(object_t *ptr, uint32_t rights, active_event_t *event) {
    process_t *self = (process_t *)ptr;

    switch (event->source.type) {
    case HYDROGEN_EVENT_PROCESS_SIGNAL:
        if ((rights & HYDROGEN_PROCESS_WAIT_SIGNAL) == 0) return EBADF;
        return event_source_add(&self->sig_target.event_source, event);
    case HYDROGEN_EVENT_PROCESS_STATUS:
        if ((rights & HYDROGEN_PROCESS_WAIT_STATUS) == 0) return EBADF;
        return event_source_add(&self->status_event, event);
    default: return EINVAL;
    }
}

static void process_event_del(object_t *ptr, active_event_t *event) {
    process_t *self = (process_t *)ptr;

    switch (event->source.type) {
    case HYDROGEN_EVENT_PROCESS_SIGNAL: return event_source_del(&self->sig_target.event_source, event);
    case HYDROGEN_EVENT_PROCESS_STATUS: return event_source_del(&self->status_event, event);
    default: UNREACHABLE();
    }
}

static const object_ops_t process_ops = {
    .free = process_free,
    .event_add = process_event_add,
    .event_del = process_event_del,
};

static void alarm_trigger(timer_event_t *timer) {
    process_t *process = CONTAINER(process_t, alarm_event, timer);
    spin_acq_noirq(&process->alarm_lock);

    if (arch_read_time() >= process->alarm_event.deadline) {
        process->alarm_queued = true;
        schedule_kernel_task(&process->alarm_task);
    }

    spin_rel_noirq(&process->alarm_lock);
}

static void alarm_send(task_t *task) {
    process_t *process = CONTAINER(process_t, alarm_task, task);
    __siginfo_t info = {.__signo = __SIGALRM, .__code = __SI_TIMER};
    queue_signal(process, &process->sig_target, &info, 0, &process->alarm_sig);

    irq_state_t state = spin_acq(&process->alarm_lock);
    process->alarm_queued = false;
    spin_rel(&process->alarm_lock, state);
}

static void proc_init(void) {
    init_pids();

    kernel_process.base.ops = &process_ops;
    obj_init(&kernel_process.base, OBJECT_PROCESS);

    kernel_process.alarm_event.func = alarm_trigger;
    kernel_process.alarm_task.func = alarm_send;

    int error = allocate_pid(&kernel_process, NULL);
    if (unlikely(error)) panic("proc: failed to allocate pid for kernel process (%e)", error);

    pid_t *pid = kernel_process.pid;
    ASSERT(pid->id == 0);

    pid->group = &kernel_group;
    pid->group->pid = pid;

    pid->session = &kernel_session;
    pid->session->pid = pid;

    ident_t *ident = vmalloc(sizeof(*ident));
    if (unlikely(!ident)) panic("proc: failed to create init identity");
    memset(ident, 0, sizeof(*ident));
    ident->references = REF_INIT(1);
    kernel_process.identity = ident;

    kernel_process.group = &kernel_group;
    list_insert_tail(&kernel_group.members, &kernel_process.group_node);
    pgroup_ref(&kernel_group);

    kernel_group.session = &kernel_session;
    session_ref(&kernel_session);
}

INIT_DEFINE_EARLY(processes, proc_init, INIT_REFERENCE(memory), INIT_REFERENCE(rcu));

static inline bool is_resolved_pid_valid(pid_t *pid) {
    return (uintptr_t)pid & (1ul << (sizeof(pid_t *) * 8 - 1));
}

static int get_pid(pid_t **out, int id) {
    if (unlikely(id < 0)) return EINVAL;
    if (unlikely((size_t)id >= pids_capacity)) return ESRCH;

    pid_t *pid = pid_table[id].allocated;
    if (unlikely(!is_resolved_pid_valid(pid))) return ESRCH;

    *out = pid;
    return 0;
}

int resolve_thread(struct thread **out, int tid) {
    mutex_acq(&pids_lock, 0, false);

    pid_t *pid;
    int error = get_pid(&pid, tid);
    thread_t *thread;

    if (likely(!error)) {
        thread = pid->thread;
        if (likely(thread)) obj_ref(&thread->base);
        else error = ESRCH;
    }

    mutex_rel(&pids_lock);
    if (unlikely(error)) return ESRCH;

    *out = thread;
    return 0;
}

int resolve_process(process_t **out, int id) {
    mutex_acq(&pids_lock, 0, false);

    pid_t *pid;
    int error = get_pid(&pid, id);
    process_t *process;

    if (likely(!error)) {
        process = pid->process;
        if (likely(process)) obj_ref(&process->base);
        else error = ESRCH;
    }

    mutex_rel(&pids_lock);
    if (unlikely(error)) return ESRCH;

    *out = process;
    return 0;
}

int resolve_pgroup(pgroup_t **out, int pgid) {
    mutex_acq(&pids_lock, 0, false);

    pid_t *pid;
    int error = get_pid(&pid, pgid);
    pgroup_t *group;

    if (likely(!error)) {
        group = pid->group;
        if (likely(group)) pgroup_ref(group);
        else error = ESRCH;
    }

    mutex_rel(&pids_lock);
    if (unlikely(error)) return ESRCH;

    *out = group;
    return 0;
}

int resolve_session(session_t **out, int sid) {
    mutex_acq(&pids_lock, 0, false);

    pid_t *pid;
    int error = get_pid(&pid, sid);
    session_t *session;

    if (likely(!error)) {
        session = pid->session;
        if (likely(session)) session_ref(session);
        else error = ESRCH;
    }

    mutex_rel(&pids_lock);
    if (unlikely(error)) return ESRCH;

    *out = session;
    return 0;
}

int proc_clone(process_t **out) {
    process_t *process = vmalloc(sizeof(*process));
    if (unlikely(!process)) return ENOMEM;
    memset(process, 0, sizeof(*process));

    process->base.ops = &process_ops;
    obj_init(&process->base, OBJECT_PROCESS);
    process->parent = current_thread->process;
    process->identity = ident_get(current_thread->process);

    mutex_acq(&current_thread->process->sig_lock, 0, false);
    memcpy(process->sig_handlers, current_thread->process->sig_handlers, sizeof(current_thread->process->sig_handlers));
    mutex_rel(&current_thread->process->sig_lock);

    process->alarm_event.func = alarm_trigger;
    process->alarm_task.func = alarm_send;

    process->umask = __atomic_load_n(&current_thread->process->umask, __ATOMIC_ACQUIRE);
    rcu_read_lock();
    process->work_dir = rcu_read(current_thread->process->work_dir);
    process->root_dir = rcu_read(current_thread->process->root_dir);
    process->group = rcu_read(current_thread->process->group);
    dentry_ref(process->work_dir);
    dentry_ref(process->root_dir);
    pgroup_ref(process->group);
    rcu_read_unlock();

    mutex_acq(&pids_lock, 0, false);
    int error = allocate_pid(process, NULL);
    mutex_rel(&pids_lock);

    if (unlikely(error)) {
        dentry_deref(process->work_dir);
        dentry_deref(process->root_dir);
        pgroup_deref(process->group);
        ident_deref(process->identity);
        vfree(process, sizeof(*process));
        return error;
    }

    obj_ref(&process->parent->base);
    mutex_acq(&process->parent->children_lock, 0, false);
    list_insert_tail(&process->parent->children, &process->parent_node);
    mutex_rel(&process->parent->children_lock);

    mutex_acq(&process->group->members_lock, 0, false);
    list_insert_tail(&process->group->members, &process->group_node);
    mutex_rel(&process->group->members_lock);

    mutex_acq(&current_thread->process->waitid_lock, 0, false);
    list_insert_tail(&current_thread->process->waitid_available, &process->waitid_node);
    mutex_rel(&current_thread->process->waitid_lock);

    *out = process;
    return 0;
}

int proc_thread_create(process_t *process, struct thread *thread) {
    mutex_acq(&process->threads_lock, 0, false);

    if (unlikely(process->exiting)) {
        mutex_rel(&process->threads_lock);
        return EPERM;
    }

    if (list_empty(&process->threads)) {
        mutex_acq(&pids_lock, 0, false);
        thread->pid = process->pid;
        thread->pid->thread = thread;
        mutex_rel(&pids_lock);
    } else if (process != current_thread->process) {
        mutex_rel(&process->threads_lock);
        return EPERM;
    } else if (process != &kernel_process) {
        mutex_acq(&pids_lock, 0, false);
        int error = allocate_pid(NULL, thread);
        mutex_rel(&pids_lock);

        if (unlikely(error)) {
            mutex_rel(&process->threads_lock);
            return error;
        }
    }

    list_insert_tail(&process->threads, &thread->process_node);

    mutex_rel(&process->threads_lock);
    return 0;
}

// returns the parent process with its children_lock held
// holding children_lock prevents the parent from reparenting us away
static process_t *get_parent_with_locked_children(process_t *process) {
    for (;;) {
        rcu_read_lock();
        process_t *parent = rcu_read(process->parent);
        obj_ref(&parent->base);
        rcu_read_unlock();

        mutex_acq(&parent->children_lock, 0, false);

        rcu_read_lock();
        bool ok = rcu_read(process->parent) == parent;
        rcu_read_unlock();

        if (ok) return parent;

        mutex_rel(&parent->children_lock);
        obj_deref(&parent->base);
    }
}

static void reap_process(process_t *process, process_t *parent) {
    list_remove(&parent->children, &process->parent_node);

    if (!process->exit_signal_sent || process->have_status) {
        mutex_acq(&parent->waitid_lock, 0, false);

        list_remove(&parent->waitid_available, &process->waitid_node);

        LIST_FOREACH(parent->waitid_waiting, thread_t, wait_node, thread) {
            sched_wake(thread);
        }

        mutex_rel(&parent->waitid_lock);
    }

    obj_deref(&parent->base);
}

static bool does_inhibit_orphaning(pgroup_t *parent_group, pgroup_t *child_group) {
    return parent_group != child_group && parent_group->session == child_group->session;
}

static void handle_process_group_orphaned(process_t *process) {
    mutex_acq(&process->sig_lock, 0, false);
    mutex_acq(&process->threads_lock, 0, false);
    mutex_acq(&process->sig_target.lock, 0, false);

    __siginfo_t info = {.__signo = __SIGHUP};
    queue_signal_unlocked(process, &process->sig_target, &info, 0, &process->hup_sig);
    info = (__siginfo_t){.__signo = __SIGCONT};
    queue_signal_unlocked(process, &process->sig_target, &info, 0, &process->cont_sig);

    mutex_rel(&process->sig_target.lock);
    mutex_rel(&process->threads_lock);
    mutex_rel(&process->sig_lock);
}

static void handle_group_orphaned(pgroup_t *group) {
    mutex_acq(&group->members_lock, 0, false);

    bool have_stopped = false;

    LIST_FOREACH(group->members, process_t, group_node, process) {
        if (have_stopped) {
            handle_process_group_orphaned(process);
        } else if (__atomic_load_n(&process->stopped, __ATOMIC_ACQUIRE)) {
            LIST_FOREACH(group->members, process_t, group_node, cur) {
                handle_process_group_orphaned(cur);
                if (process == cur) break;
            }

            have_stopped = true;
        }
    }

    mutex_rel(&group->members_lock);
    pgroup_deref(group);
}

static void reparent_children(process_t *process) {
    ASSERT(init_process != NULL);

    mutex_acq(&process->children_lock, 0, false);

    for (;;) {
        process_t *child = LIST_REMOVE_HEAD(process->children, process_t, parent_node);
        if (!child) break;

        rcu_read_lock();

        pgroup_t *opgroup = process->group;
        pgroup_t *npgroup = init_process->group;
        pgroup_t *cgroup = child->group;

        bool old_inhibit = does_inhibit_orphaning(opgroup, cgroup);
        bool new_inhibit = does_inhibit_orphaning(npgroup, cgroup);
        bool newly_orphaned = false;

        if (old_inhibit) {
            if (!new_inhibit && __atomic_fetch_sub(&cgroup->orphan_inhibitors, 1, __ATOMIC_ACQ_REL) == 1) {
                newly_orphaned = true;
                pgroup_ref(cgroup);
            }
        } else if (new_inhibit) {
            __atomic_fetch_add(&cgroup->orphan_inhibitors, 1, __ATOMIC_ACQ_REL);
        }

        rcu_read_unlock();

        if (newly_orphaned) {
            handle_group_orphaned(cgroup);
            pgroup_deref(cgroup);
        }

        mutex_acq(&child->status_lock, 0, false);
        mutex_acq(&init_process->children_lock, 0, false);
        obj_deref(&process->base);
        obj_ref(&init_process->base);
        list_insert_tail(&init_process->children, &child->parent_node);
        rcu_write(child->parent, init_process);
        mutex_rel(&init_process->children_lock);

        if (child->have_status) {
            mutex_acq(&init_process->sig_lock, 0, false);
            mutex_acq(&init_process->threads_lock, 0, false);
            mutex_acq(&init_process->sig_target.lock, 0, false);

            unsigned code = child->chld_sig.info.__code;
            if ((code != __CLD_CONTINUED && code != __CLD_STOPPED) ||
                (init_process->sig_handlers[__SIGCHLD].__flags & __SA_NOCLDSTOP) == 0) {
                queue_signal_unlocked(
                    init_process,
                    &init_process->sig_target,
                    &child->chld_sig.info,
                    0,
                    &child->chld_sig
                );
            }

            mutex_rel(&init_process->sig_lock);
            mutex_rel(&init_process->threads_lock);
            mutex_rel(&init_process->sig_target.lock);
        }

        if (!child->exit_signal_sent || child->have_status) {
            mutex_acq(&init_process->waitid_lock, 0, false);

            list_insert_tail(&init_process->waitid_available, &child->waitid_node);

            if (child->have_status) {
                LIST_FOREACH(init_process->waitid_waiting, thread_t, wait_node, thread) {
                    sched_wake(thread);
                }
            }

            mutex_rel(&init_process->waitid_lock);
        }

        mutex_rel(&child->status_lock);
    }

    mutex_rel(&process->children_lock);
    rcu_sync();
}

static void do_leave_group(pgroup_t *group, process_t *process) {
    list_remove(&group->members, &process->group_node);

    if (list_empty(&group->members)) {
        __atomic_fetch_sub(&group->session->num_members, 1, __ATOMIC_RELEASE);
    }
}

static void leave_group(pgroup_t *group, process_t *process) {
    mutex_acq(&group->members_lock, 0, false);
    do_leave_group(group, process);
    mutex_rel(&group->members_lock);
}

static void handle_status_change(process_t *process, process_t *parent, __siginfo_t *info) {
    process->chld_sig.info = *info;
    process->have_status = true;
    event_source_signal(&process->status_event);

    LIST_FOREACH(process->waiters, thread_t, wait_node, thread) {
        sched_wake(thread);
    }
}

static void discard_status(process_t *process, process_t *parent, bool own_waitid_lock) {
    process->have_status = false;
    event_source_reset(&process->status_event);

    LIST_FOREACH(process->waiters, thread_t, wait_node, thread) {
        sched_wake(thread);
    }

    if (process->exit_signal_sent) {
        if (!own_waitid_lock) mutex_acq(&parent->waitid_lock, 0, false);

        list_remove(&parent->waitid_available, &process->waitid_node);

        LIST_FOREACH(parent->waitid_waiting, thread_t, wait_node, thread) {
            sched_wake(thread);
        }

        if (!own_waitid_lock) mutex_rel(&parent->waitid_lock);

        reap_process(process, parent);
        obj_deref(&process->base);
    }
}

static void handle_process_exit(process_t *process) {
    ASSERT(process != &kernel_process);

    if (process == init_process) {
        mutex_acq(&process->status_lock, 0, false);

        const char *type;
        int status;

        if (process->exit_signal_sent) {
            switch (process->chld_sig.info.__code) {
            case __CLD_KILLED: type = "kill"; break;
            case __CLD_DUMPED: type = "kill with core dump"; break;
            default: UNREACHABLE();
            }

            status = process->chld_sig.info.__data.__user_or_sigchld.__status;
        } else {
            type = "exit";
            status = process->exit_status;
        }

        mutex_rel(&process->status_lock);
        panic("init tried to exit! type: %s, status: %d", type, status);
    }

    reparent_children(process);

    rcu_read_lock();
    pgroup_t *pgroup = rcu_read(rcu_read(process->parent)->group);
    pgroup_t *cgroup = rcu_read(process->group);
    pgroup_ref(cgroup);
    bool newly_orphaned = does_inhibit_orphaning(pgroup, cgroup) &&
                          __atomic_fetch_sub(&cgroup->orphan_inhibitors, 1, __ATOMIC_ACQ_REL) == 1;
    rcu_read_unlock();

    leave_group(process->group, process);

    if (newly_orphaned) {
        handle_group_orphaned(cgroup);
    }

    pgroup_deref(cgroup);

    __siginfo_t info = {
        .__signo = __SIGCHLD,
        .__code = __CLD_EXITED,
        .__data.__user_or_sigchld.__pid = getpid(process),
        .__data.__user_or_sigchld.__status = process->exit_status,
        .__data.__user_or_sigchld.__uid = getuid(process),
    };

    mutex_acq(&process->status_lock, 0, false);

    process_t *parent = get_parent_with_locked_children(process);
    mutex_acq(&parent->sig_lock, 0, false);

    if (!process->exit_signal_sent) {
        process->exit_signal_sent = true;
        obj_ref(&process->base);

        mutex_acq(&parent->threads_lock, 0, false);
        mutex_acq(&parent->sig_target.lock, 0, false);

        handle_status_change(process, parent, &info);
        queue_signal_unlocked(parent, &parent->sig_target, &info, 0, &process->chld_sig);

        mutex_rel(&parent->sig_target.lock);
        mutex_rel(&parent->threads_lock);
    }

    bool should_reap = parent->sig_handlers[__SIGCHLD].__func.__handler == __SIG_IGN ||
                       parent->sig_handlers[__SIGCHLD].__flags & __SA_NOCLDWAIT;
    if (should_reap) discard_status(process, parent, false);

    mutex_rel(&parent->sig_lock);
    mutex_rel(&process->status_lock);

    mutex_rel(&parent->children_lock);
    obj_deref(&parent->base);
}

void proc_thread_exit(process_t *process, struct thread *thread, int status) {
    mutex_acq(&process->threads_lock, 0, false);
    list_remove(&process->threads, &thread->process_node);

    bool proc_exit = list_empty(&process->threads);

    if (!proc_exit) {
        if (process->threads.head == process->threads.tail && process->singlethreaded_handler != NULL) {
            sched_wake(process->singlethreaded_handler);
        }
    } else {
        process->exit_status = status;
        __atomic_store_n(&process->exiting, true, __ATOMIC_RELEASE);
    }

    mutex_rel(&process->threads_lock);
    if (proc_exit) handle_process_exit(process);
}

void handle_process_terminated(process_t *process, int signal, bool dump) {
    __siginfo_t info = {
        .__signo = __SIGCHLD,
        .__code = dump ? __CLD_DUMPED : __CLD_KILLED,
        .__data.__user_or_sigchld.__pid = getpid(process),
        .__data.__user_or_sigchld.__status = signal,
        .__data.__user_or_sigchld.__uid = getuid(process),
    };

    mutex_acq(&process->status_lock, 0, false);

    process_t *parent = get_parent_with_locked_children(process);
    mutex_acq(&parent->sig_lock, 0, false);

    mutex_acq(&parent->threads_lock, 0, false);
    mutex_acq(&parent->sig_target.lock, 0, false);

    handle_status_change(process, parent, &info);
    queue_signal_unlocked(parent, &parent->sig_target, &info, 0, &process->chld_sig);

    mutex_rel(&parent->sig_target.lock);
    mutex_rel(&parent->threads_lock);

    mutex_rel(&parent->sig_lock);
    mutex_rel(&parent->children_lock);

    process->exit_signal_sent = true;
    obj_ref(&process->base);
    mutex_rel(&process->status_lock);
}

void handle_process_stopped(process_t *process, int signal) {
    __siginfo_t info = {
        .__signo = __SIGCHLD,
        .__code = __CLD_STOPPED,
        .__data.__user_or_sigchld.__pid = getpid(process),
        .__data.__user_or_sigchld.__status = signal,
        .__data.__user_or_sigchld.__uid = getuid(process),
    };

    mutex_acq(&process->status_lock, 0, false);

    process_t *parent = get_parent_with_locked_children(process);
    mutex_acq(&parent->sig_lock, 0, false);

    handle_status_change(process, parent, &info);

    if ((parent->sig_handlers[__SIGCHLD].__flags & __SA_NOCLDSTOP) == 0) {
        mutex_acq(&parent->threads_lock, 0, false);
        mutex_acq(&parent->sig_target.lock, 0, false);
        queue_signal_unlocked(parent, &parent->sig_target, &info, 0, &process->chld_sig);
        mutex_rel(&parent->sig_target.lock);
        mutex_rel(&parent->threads_lock);
    }

    mutex_rel(&parent->sig_lock);
    mutex_rel(&parent->children_lock);
    mutex_rel(&process->status_lock);
}

void handle_process_continued(process_t *process, int signal) {
    __siginfo_t info = {
        .__signo = __SIGCHLD,
        .__code = __CLD_CONTINUED,
        .__data.__user_or_sigchld.__pid = getpid(process),
        .__data.__user_or_sigchld.__status = signal,
        .__data.__user_or_sigchld.__uid = getuid(process),
    };

    mutex_acq(&process->status_lock, 0, false);

    process_t *parent = get_parent_with_locked_children(process);
    mutex_acq(&parent->sig_lock, 0, false);

    handle_status_change(process, parent, &info);

    if ((parent->sig_handlers[__SIGCHLD].__flags & __SA_NOCLDSTOP) == 0) {
        mutex_acq(&parent->threads_lock, 0, false);
        mutex_acq(&parent->sig_target.lock, 0, false);
        queue_signal_unlocked(parent, &parent->sig_target, &info, 0, &process->chld_sig);
        mutex_rel(&parent->sig_target.lock);
        mutex_rel(&parent->threads_lock);
    }

    mutex_rel(&parent->sig_lock);
    mutex_rel(&parent->children_lock);
    mutex_rel(&process->status_lock);
}

static bool status_qualifies(process_t *process, unsigned flags) {
    switch (process->chld_sig.info.__code) {
    case __CLD_EXITED: return flags & HYDROGEN_PROCESS_WAIT_EXITED;
    case __CLD_KILLED:
    case __CLD_DUMPED: return flags & HYDROGEN_PROCESS_WAIT_KILLED;
    case __CLD_STOPPED: return flags & HYDROGEN_PROCESS_WAIT_STOPPED;
    case __CLD_CONTINUED: return flags & HYDROGEN_PROCESS_WAIT_CONTINUED;
    default: return false;
    }
}

static void handle_got_status(process_t *process, unsigned flags, bool own_waitid_lock) {
    if ((flags & HYDROGEN_PROCESS_WAIT_DISCARD) != 0) {
        process_t *parent = get_parent_with_locked_children(process);

        if (process->exit_signal_sent) {
            __atomic_fetch_add(
                &parent->child_kern_time,
                process->kern_time + process->child_kern_time,
                __ATOMIC_RELAXED
            );
            __atomic_fetch_add(
                &parent->child_user_time,
                process->user_time + process->child_user_time,
                __ATOMIC_RELAXED
            );
        }

        discard_status(process, parent, own_waitid_lock);

        mutex_rel(&parent->children_lock);
        obj_deref(&parent->base);
    }

    if ((flags & HYDROGEN_PROCESS_WAIT_UNQUEUE) != 0) {
        unqueue_signal(&process->chld_sig);
    }
}

int proc_wait(process_t *process, unsigned flags, __siginfo_t *info, uint64_t deadline) {
    mutex_acq(&process->status_lock, 0, false);

    while (!process->have_status || !status_qualifies(process, flags)) {
        if (deadline == 1) {
            mutex_rel(&process->status_lock);
            return EAGAIN;
        }

        sched_prepare_wait(true);
        list_insert_tail(&process->waiters, &current_thread->wait_node);
        mutex_rel(&process->status_lock);
        int error = sched_perform_wait(deadline);
        mutex_acq(&process->status_lock, 0, false);
        list_remove(&process->waiters, &current_thread->wait_node);

        if (unlikely(error)) {
            mutex_rel(&process->status_lock);
            return error == ETIMEDOUT ? EAGAIN : error;
        }
    }

    int error = user_memcpy(info, &process->chld_sig.info, sizeof(*info));
    if (unlikely(error)) {
        mutex_rel(&process->status_lock);
        return error;
    }

    handle_got_status(process, flags, false);
    mutex_rel(&process->status_lock);

    return 0;
}

hydrogen_ret_t proc_waitid(int id, unsigned flags, __siginfo_t *info, uint64_t deadline) {
    process_t *parent = current_thread->process;

again:
    mutex_acq(&parent->waitid_lock, 0, false);

    for (;;) {
        bool have_candidate = false;

        LIST_FOREACH(parent->waitid_available, process_t, waitid_node, process) {
            if (id == 0 || getpgid(process) == id) {
                have_candidate = true;

                if (!mutex_try_acq(&process->status_lock)) {
                    obj_ref(&process->base);
                    mutex_rel(&parent->waitid_lock);
                    mutex_acq(&process->status_lock, 0, false);
                    mutex_rel(&process->status_lock);
                    obj_deref(&process->base);
                    goto again;
                }

                if (process->have_status && status_qualifies(process, flags)) {
                    int error = user_memcpy(info, &process->chld_sig.info, sizeof(*info));

                    if (unlikely(error)) {
                        mutex_rel(&process->status_lock);
                        mutex_rel(&parent->waitid_lock);
                        return ret_error(error);
                    }

                    obj_ref(&process->base);
                    handle_got_status(process, flags, true);

                    int id = process->pid->id;
                    mutex_rel(&process->status_lock);
                    mutex_rel(&parent->waitid_lock);
                    obj_deref(&process->base);
                    return ret_integer(id);
                }

                mutex_rel(&process->status_lock);
            }
        }

        if (!have_candidate) {
            mutex_rel(&parent->waitid_lock);
            return ret_error(ECHILD);
        }

        if (deadline == 1) {
            mutex_rel(&parent->waitid_lock);
            return ret_error(EAGAIN);
        }

        sched_prepare_wait(true);
        list_insert_tail(&parent->waitid_waiting, &current_thread->wait_node);
        mutex_rel(&parent->waitid_lock);
        int error = sched_perform_wait(deadline);
        mutex_acq(&parent->waitid_lock, 0, false);
        list_remove(&parent->waitid_waiting, &current_thread->wait_node);

        if (unlikely(error)) {
            mutex_rel(&parent->waitid_lock);
            return ret_error(error == ETIMEDOUT ? EAGAIN : error);
        }
    }
}

uint64_t proc_alarm(process_t *process, uint64_t time) {
    irq_state_t state = spin_acq(&process->alarm_lock);

    while (process->alarm_queued) {
        list_insert_tail(&process->alarm_waiting, &current_thread->wait_node);
        sched_prepare_wait(false);
        spin_rel(&process->alarm_lock, state);
        sched_perform_wait(0);
        state = spin_acq(&process->alarm_lock);
    }

    uint64_t prev_time = process->alarm_event.deadline;
    if (prev_time) timer_cancel_event(&process->alarm_event);

    process->alarm_event.deadline = time;

    if (time) timer_queue_event(&process->alarm_event);

    spin_rel(&process->alarm_lock, state);
    return prev_time;
}

void proc_wait_until_single_threaded(void) {
    process_t *process = current_thread->process;
    ASSERT(process->exiting);

    while (process->threads.head != process->threads.tail) {
        process->singlethreaded_handler = current_thread;
        sched_prepare_wait(false);
        mutex_rel(&process->threads_lock);
        sched_perform_wait(0);
        mutex_acq(&process->threads_lock, 0, false);
        process->singlethreaded_handler = NULL;
    }
}

int sigaction(process_t *process, int signal, const struct __sigaction *action, struct __sigaction *old) {
    ASSERT(signal >= 1 && signal < __NSIG);

    mutex_acq(&process->sig_lock, 0, false);

    struct __sigaction old_act = process->sig_handlers[signal];

    if (old) {
        int error = user_memcpy(old, &old_act, sizeof(old_act));

        if (unlikely(error)) {
            mutex_rel(&process->sig_lock);
            return error;
        }
    }

    if (action) {
        struct __sigaction new_act;
        int error = user_memcpy(&new_act, action, sizeof(*action));

        if (unlikely(error)) {
            mutex_rel(&process->sig_lock);
            return error;
        }

        if (new_act.__func.__handler != __SIG_DFL) {
            if ((signal == __SIGKILL || signal == __SIGSTOP) ||
                (new_act.__func.__handler != __SIG_IGN &&
                 (uintptr_t)new_act.__func.__handler > arch_pt_max_user_addr())) {
                mutex_rel(&process->sig_lock);
                return EINVAL;
            }
        }

        if (get_sig_disp(signal, &old_act) != SIGNAL_IGNORE && get_sig_disp(signal, &new_act) == SIGNAL_IGNORE) {
            mutex_acq(&process->threads_lock, 0, false);

            handle_signal_ignored(&process->sig_target, signal);

            LIST_FOREACH(process->threads, thread_t, process_node, thread) {
                handle_signal_ignored(&thread->sig_target, signal);
            }

            mutex_rel(&process->threads_lock);
        }

        process->sig_handlers[signal] = new_act;
    }

    mutex_rel(&process->sig_lock);
    return 0;
}

int sigwait(process_t *process, __sigset_t set, __siginfo_t *info, uint64_t deadline) {
    bool check_thread = process == current_thread->process;

    mutex_acq(&process->sig_lock, 0, false);
    mutex_acq(&process->threads_lock, 0, false);

    if (check_thread) {
        mutex_acq(&current_thread->sig_target.lock, 0, false);

        queued_signal_t *sig = get_queued_signal(&current_thread->sig_target, set, current_thread->sig_mask);

        if (sig != NULL) {
            int error = user_memcpy(info, &sig->info, sizeof(*info));
            if (likely(error == 0)) remove_queued_signal(&current_thread->sig_target, sig);
            mutex_rel(&current_thread->sig_target.lock);
            mutex_rel(&process->threads_lock);
            mutex_rel(&process->sig_lock);
            return error;
        }
    }

    mutex_acq(&process->sig_target.lock, 0, false);

    queued_signal_t *sig = get_queued_signal(&process->sig_target, set, current_thread->sig_mask);

    if (sig != NULL) {
        int error = user_memcpy(info, &sig->info, sizeof(*info));
        if (likely(error == 0)) remove_queued_signal(&current_thread->sig_target, sig);
        mutex_rel(&process->sig_target.lock);
        if (check_thread) mutex_rel(&current_thread->sig_target.lock);
        mutex_rel(&process->threads_lock);
        mutex_rel(&process->sig_lock);
        return error;
    }

    int error = EAGAIN;

    if (deadline != 1) {
        signal_waiter_t proc_wait, thread_wait;
        proc_wait.set = thread_wait.set = set;
        proc_wait.thread = thread_wait.thread = current_thread;
        proc_wait.sig = thread_wait.sig = NULL;

        list_insert_tail(&process->sig_target.signal_waiters, &proc_wait.node);
        if (check_thread) list_insert_tail(&current_thread->sig_target.signal_waiters, &thread_wait.node);
        sched_prepare_wait(true);

        mutex_rel(&process->sig_target.lock);
        if (check_thread) mutex_rel(&current_thread->sig_target.lock);
        mutex_rel(&process->threads_lock);
        mutex_rel(&process->sig_lock);

        error = sched_perform_wait(deadline);
        if (error == ETIMEDOUT) error = EAGAIN;

        mutex_acq(&process->sig_lock, 0, false);
        mutex_acq(&process->threads_lock, 0, false);
        if (check_thread) mutex_acq(&current_thread->sig_target.lock, 0, false);
        mutex_acq(&process->sig_target.lock, 0, false);

        if (likely(error == 0)) {
            queued_signal_t *sig = thread_wait.sig;
            signal_target_t *target = &current_thread->sig_target;

            if (sig == NULL) {
                if (check_thread) list_remove(&current_thread->sig_target.signal_waiters, &thread_wait.node);
                sig = proc_wait.sig;
                target = &process->sig_target;
                ASSERT(sig != NULL);
            } else {
                list_remove(&process->sig_target.signal_waiters, &proc_wait.node);
            }

            error = user_memcpy(info, &sig->info, sizeof(*info));

            if (likely(error == 0)) {
                if (sig->heap) vfree(sig, sizeof(*sig));
            } else {
                add_queued_signal(process, target, sig);
            }
        } else {
            list_remove(&process->sig_target.signal_waiters, &proc_wait.node);
            if (check_thread) list_remove(&current_thread->sig_target.signal_waiters, &thread_wait.node);
        }
    }

    mutex_rel(&process->sig_target.lock);
    if (check_thread) mutex_rel(&current_thread->sig_target.lock);
    mutex_rel(&process->threads_lock);
    mutex_rel(&process->sig_lock);
    return error;
}

bool can_send_signal(process_t *process, __siginfo_t *info) {
    rcu_read_lock();

    if (info->__signo == __SIGCONT &&
        rcu_read(current_thread->process->group)->session == rcu_read(process->group->session)) {
        rcu_read_unlock();
        return true;
    }

    ident_t *rx_ident = rcu_read(process->identity);

    if (info->__data.__user_or_sigchld.__uid == rx_ident->uid ||
        info->__data.__user_or_sigchld.__uid == rx_ident->suid) {
        rcu_read_unlock();
        return true;
    }

    ident_t *tx_ident = rcu_read(current_thread->process->identity);

    if (tx_ident->euid == 0) {
        rcu_read_unlock();
        return true;
    }

    bool ok = tx_ident->euid == rx_ident->uid || tx_ident->euid == rx_ident->suid;
    rcu_read_unlock();
    return ok;
}

void create_user_siginfo(__siginfo_t *out, int signal) {
    *out = (__siginfo_t){
        .__signo = signal,
        .__code = __SI_USER,
        .__data.__user_or_sigchld.__pid = getpid(current_thread->process),
        .__data.__user_or_sigchld.__uid = getuid(current_thread->process),
    };
}

int broadcast_signal(int signal) {
    bool sent = false;
    int error = ESRCH;

    __siginfo_t info;
    create_user_siginfo(&info, signal);

    mutex_acq(&pids_lock, 0, false);

    for (size_t i = 0; i < pids_capacity; i++) {
        pid_t *pid = pid_table[i].allocated;
        if (!is_resolved_pid_valid(pid)) continue;

        process_t *proc = pid->process;
        if (proc == NULL || proc == current_thread->process) continue;

        if (error == ESRCH) error = EPERM;

        if (can_send_signal(proc, &info)) {
            if (signal != 0) {
                int ret = queue_signal(proc, &proc->sig_target, &info, 0, NULL);
                if (likely(ret == 0)) sent = true;
                else if (error == EPERM) error = ret;
            } else {
                sent = true;
                goto done;
            }
        }
    }

done:
    mutex_rel(&pids_lock);
    return sent ? 0 : error;
}

int group_signal(pgroup_t *group, int signal) {
    bool sent = false;
    int error = ESRCH;

    __siginfo_t info;
    create_user_siginfo(&info, signal);

    mutex_acq(&group->members_lock, 0, false);

    LIST_FOREACH(group->members, process_t, group_node, proc) {
        if (error == ESRCH) error = EPERM;

        if (can_send_signal(proc, &info)) {
            if (signal != 0) {
                int ret = queue_signal(proc, &proc->sig_target, &info, 0, NULL);
                if (likely(ret == 0)) sent = true;
                else if (error == EPERM) error = ret;
            } else {
                sent = true;
                break;
            }
        }
    }

    mutex_rel(&group->members_lock);
    return sent ? 0 : error;
}

void pgroup_ref(pgroup_t *group) {
    ref_inc(&group->references);
}

void pgroup_deref(pgroup_t *group) {
    if (ref_dec_maybe(&group->references)) {
        ASSERT(group != &kernel_group);

        pid_t *pid = group->pid;
        mutex_acq(&pids_lock, 0, false);

        if (!ref_dec(&group->references)) {
            mutex_rel(&pids_lock);
            return;
        }

        pid->group = NULL;
        pid_handle_removal_and_unlock(pid);

        session_deref(group->session);
        vfree(group, sizeof(*group));
    }
}

void session_ref(session_t *session) {
    ref_inc(&session->references);
}

void session_deref(session_t *session) {
    if (ref_dec_maybe(&session->references)) {
        ASSERT(session != &kernel_session);

        pid_t *pid = session->pid;
        mutex_acq(&pids_lock, 0, false);

        if (!ref_dec(&session->references)) {
            mutex_rel(&pids_lock);
            return;
        }

        pid->session = NULL;
        pid_handle_removal_and_unlock(pid);

        vfree(session, sizeof(*session));
    }
}

int getpid(process_t *process) {
    return process->pid->id;
}

int getppid(process_t *process) {
    rcu_read_lock();
    int id = rcu_read(process->parent)->pid->id;
    rcu_read_unlock();
    return id;
}

int getpgid(process_t *process) {
    rcu_read_lock();
    int id = rcu_read(process->group)->pid->id;
    rcu_read_unlock();
    return id;
}

int getsid(process_t *process) {
    rcu_read_lock();
    int id = rcu_read(process->group)->session->pid->id;
    rcu_read_unlock();
    return id;
}

static void do_lock_two(pgroup_t *a, pgroup_t *b) {
    if ((uintptr_t)a < (uintptr_t)b) {
        mutex_acq(&a->members_lock, 0, false);
        mutex_acq(&b->members_lock, 0, false);
    } else {
        mutex_acq(&b->members_lock, 0, false);
        mutex_acq(&a->members_lock, 0, false);
    }
}

static void do_unlock_two(pgroup_t *a, pgroup_t *b) {
    if ((uintptr_t)a < (uintptr_t)b) {
        mutex_rel(&b->members_lock);
        mutex_rel(&a->members_lock);
    } else {
        mutex_rel(&a->members_lock);
        mutex_rel(&b->members_lock);
    }
}

int setpgid(process_t *process, int pgid) {
    if (pgid < 0) return EINVAL;

    rcu_read_lock();
    session_t *own_session = rcu_read(current_thread->process->group)->session;
    session_ref(own_session);
    rcu_read_unlock();

    mutex_acq(&process->group_update_lock, 0, false);
    pgroup_t *old_group = process->group;

    int error = EPERM;
    if (unlikely(old_group->session->pid == process->pid)) goto err;
    if (unlikely(old_group->session != own_session)) goto err;

    pgroup_t *new_group;
    bool created = false;

    if (pgid == 0 || pgid == process->pid->id) {
        mutex_acq(&pids_lock, 0, false);

        if (process->pid->group) {
            new_group = process->pid->group;

            error = 0;
            if (new_group == old_group) {
                mutex_rel(&pids_lock);
                goto err;
            }

            pgroup_ref(new_group);
        } else {
            new_group = vmalloc(sizeof(*new_group));
            if (unlikely(!new_group)) {
                error = ENOMEM;
                goto err;
            }
            memset(new_group, 0, sizeof(*new_group));

            new_group->pid = process->pid;
            new_group->references = REF_INIT(1);
            new_group->session = own_session;
            session_ref(new_group->session);
            __atomic_fetch_add(&own_session->num_members, 1, __ATOMIC_ACQ_REL);
            new_group->pid->group = new_group;
            created = true;
        }

        mutex_rel(&pids_lock);
    } else {
        if (unlikely(resolve_pgroup(&new_group, pgid))) goto err;
        if (unlikely(new_group->session != own_session)) goto err;

        error = 0;
        if (new_group == old_group) goto err;
    }

    do_lock_two(old_group, new_group);

    if (!created && list_empty(&new_group->members)) {
        do_unlock_two(old_group, new_group);
        error = EPERM;
        pgroup_deref(new_group);
        goto err;
    }

    rcu_read_lock();

    pgroup_t *parent_group = rcu_read(rcu_read(process->parent)->group);
    bool old_inhibit = does_inhibit_orphaning(parent_group, old_group);
    bool new_inhibit = does_inhibit_orphaning(parent_group, new_group);
    bool newly_orphaned = old_inhibit && __atomic_fetch_sub(&old_group->orphan_inhibitors, 1, __ATOMIC_ACQ_REL) == 1;
    if (new_inhibit) __atomic_fetch_add(&new_group->orphan_inhibitors, 1, __ATOMIC_ACQ_REL);
    rcu_read_unlock();

    do_leave_group(old_group, process);
    list_insert_tail(&new_group->members, &process->group_node);
    do_unlock_two(old_group, new_group);

    if (newly_orphaned) handle_group_orphaned(old_group);

    rcu_write(process->group, new_group);
    mutex_rel(&process->group_update_lock);
    session_deref(own_session);
    rcu_sync();
    pgroup_deref(old_group);

    mutex_acq(&process->status_lock, 0, false);

    if (!process->exit_signal_sent || process->have_status) {
        // setpgid could cause a parent's waitid call to fail with ECHILD. wake all the waiters
        // to ensure they can check for it.
        process_t *parent = get_parent_with_locked_children(process);
        mutex_acq(&parent->waitid_lock, 0, false);

        LIST_FOREACH(parent->waitid_waiting, thread_t, wait_node, thread) {
            sched_wake(thread);
        }

        mutex_rel(&parent->waitid_lock);
    }

    mutex_rel(&process->status_lock);
    return 0;

err:
    mutex_rel(&process->group_update_lock);
    session_deref(own_session);
    return error;
}

hydrogen_ret_t setsid(process_t *process) {
    mutex_acq(&process->group_update_lock, 0, false);

    mutex_acq(&pids_lock, 0, false);
    bool was_leader = process->pid->group != NULL;
    mutex_rel(&pids_lock);

    if (unlikely(was_leader)) {
        mutex_rel(&process->group_update_lock);
        return ret_error(EPERM);
    }

    session_t *session = vmalloc(sizeof(*session));
    if (unlikely(session == NULL)) {
        mutex_rel(&process->group_update_lock);
        return ret_error(ENOMEM);
    }

    pgroup_t *group = vmalloc(sizeof(*group));
    if (unlikely(group == NULL)) {
        mutex_rel(&process->group_update_lock);
        vfree(session, sizeof(*session));
        return ret_error(ENOMEM);
    }

    memset(session, 0, sizeof(*session));
    memset(group, 0, sizeof(*group));

    session->pid = process->pid;
    session->references = REF_INIT(1);

    group->pid = process->pid;
    group->references = REF_INIT(1);
    group->session = session;

    pgroup_t *old_group = process->group;

    rcu_read_lock();
    bool newly_orphaned = does_inhibit_orphaning(rcu_read(rcu_read(process->parent)->group), old_group) &&
                          __atomic_fetch_sub(&old_group->orphan_inhibitors, 1, __ATOMIC_ACQ_REL) == 1;
    rcu_read_unlock();

    leave_group(old_group, process);

    if (newly_orphaned) handle_group_orphaned(old_group);

    list_insert_tail(&group->members, &process->group_node);

    mutex_acq(&pids_lock, 0, false);
    group->pid->session = session;
    group->pid->group = group;
    mutex_rel(&pids_lock);

    rcu_write(process->group, group);
    mutex_rel(&process->group_update_lock);
    rcu_sync();
    pgroup_deref(old_group);
    return ret_integer(process->pid->id);
}

uint32_t getgid(process_t *process) {
    rcu_read_lock();
    uint32_t gid = rcu_read(process->identity)->gid;
    rcu_read_unlock();
    return gid;
}

uint32_t getuid(process_t *process) {
    rcu_read_lock();
    uint32_t uid = rcu_read(process->identity)->uid;
    rcu_read_unlock();
    return uid;
}

uint32_t getegid(process_t *process) {
    rcu_read_lock();
    uint32_t egid = rcu_read(process->identity)->egid;
    rcu_read_unlock();
    return egid;
}

uint32_t geteuid(process_t *process) {
    rcu_read_lock();
    uint32_t euid = rcu_read(process->identity)->euid;
    rcu_read_unlock();
    return euid;
}

int getresgid(process_t *process, uint32_t gids[3]) {
    uint32_t src[3];

    rcu_read_lock();
    ident_t *ident = rcu_read(process->identity);
    src[0] = ident->gid;
    src[1] = ident->egid;
    src[2] = ident->sgid;
    rcu_read_unlock();

    return user_memcpy(gids, src, sizeof(src));
}

int getresuid(process_t *process, uint32_t uids[3]) {
    uint32_t src[3];

    rcu_read_lock();
    ident_t *ident = rcu_read(process->identity);
    src[0] = ident->uid;
    src[1] = ident->euid;
    src[2] = ident->suid;
    rcu_read_unlock();

    return user_memcpy(uids, src, sizeof(src));
}

int getgroups(process_t *process, uint32_t *buffer, size_t *count) {
    ident_t *ident = ident_get(process);

    size_t cur = *count;
    if (cur > ident->num_groups) cur = ident->num_groups;
    *count = ident->num_groups;
    int error = user_memcpy(buffer, ident->groups, cur * sizeof(*buffer));

    ident_deref(ident);
    return error;
}

ident_t *ident_copy(ident_t *src) {
    ident_t *copy = vmalloc(sizeof(*copy));
    if (unlikely(!copy)) return NULL;

    copy->groups = vmalloc(src->num_groups * sizeof(*copy->groups));
    if (unlikely(!copy->groups)) return NULL;
    memcpy(copy->groups, src->groups, src->num_groups * sizeof(*copy->groups));
    copy->num_groups = src->num_groups;

    copy->references = REF_INIT(1);
    copy->uid = src->uid;
    copy->gid = src->gid;
    copy->euid = src->euid;
    copy->egid = src->egid;
    copy->suid = src->suid;
    copy->sgid = src->sgid;
    return copy;
}

#define update_identity(check, update)                    \
    ({                                                    \
        mutex_acq(&process->ident_update_lock, 0, false); \
                                                          \
        ident_t *old_ident = process->identity;           \
                                                          \
        if (old_ident->euid != 0 && !(check)) {           \
            mutex_rel(&process->ident_update_lock);       \
            return EPERM;                                 \
        }                                                 \
                                                          \
        ident_t *new_ident = ident_copy(old_ident);       \
        if (unlikely(!new_ident)) {                       \
            mutex_rel(&process->ident_update_lock);       \
            return ENOMEM;                                \
        }                                                 \
                                                          \
        int error = (update);                             \
        if (unlikely(error)) {                            \
            ident_deref(new_ident);                       \
            mutex_rel(&process->ident_update_lock);       \
            return error;                                 \
        }                                                 \
                                                          \
        rcu_write(process->identity, new_ident);          \
        mutex_rel(&process->ident_update_lock);           \
        rcu_sync();                                       \
        ident_deref(old_ident);                           \
        return 0;                                         \
    })

int setgid(process_t *process, uint32_t gid) {
    if (gid == (uint32_t)-1) return EINVAL;

    update_identity(gid == old_ident->gid || gid == old_ident->sgid, ({
                        if (old_ident->euid == 0) {
                            new_ident->gid = gid;
                            new_ident->egid = gid;
                            new_ident->sgid = gid;
                        } else {
                            new_ident->egid = gid;
                        }
                        0;
                    }));
}

int setuid(process_t *process, uint32_t uid) {
    if (uid == (uint32_t)-1) return EINVAL;

    update_identity(uid == old_ident->uid || uid == old_ident->suid, ({
                        if (old_ident->euid == 0) {
                            new_ident->uid = uid;
                            new_ident->euid = uid;
                            new_ident->suid = uid;
                        } else {
                            new_ident->euid = uid;
                        }
                        0;
                    }));
}

int setegid(process_t *process, uint32_t egid) {
    if (egid == (uint32_t)-1) return EINVAL;

    update_identity(egid == old_ident->gid || egid == old_ident->egid || egid == old_ident->sgid, ({
                        new_ident->egid = egid;
                        0;
                    }));
}

int seteuid(process_t *process, uint32_t euid) {
    if (euid == (uint32_t)-1) return EINVAL;

    update_identity(euid == old_ident->uid || euid == old_ident->euid || euid == old_ident->suid, ({
                        new_ident->euid = euid;
                        0;
                    }));
}

int setregid(process_t *process, uint32_t gid, uint32_t egid) {
    update_identity(
        (gid == (uint32_t)-1 || gid == old_ident->gid || gid == old_ident->sgid) &&
            (egid == (uint32_t)-1 || egid == old_ident->gid || egid == old_ident->egid || egid == old_ident->sgid),
        ({
            if (egid != (uint32_t)-1) {
                new_ident->egid = egid;
                if (egid != new_ident->gid) new_ident->sgid = egid;
            }

            if (gid != (uint32_t)-1) {
                new_ident->gid = gid;
                new_ident->sgid = new_ident->egid;
            }

            0;
        })
    );
}

int setreuid(process_t *process, uint32_t uid, uint32_t euid) {
    update_identity(
        (uid == (uint32_t)-1 || uid == old_ident->uid || uid == old_ident->suid) &&
            (euid == (uint32_t)-1 || euid == old_ident->uid || euid == old_ident->euid || euid == old_ident->suid),
        ({
            if (euid != (uint32_t)-1) {
                new_ident->euid = euid;
                if (euid != new_ident->uid) new_ident->suid = euid;
            }

            if (uid != (uint32_t)-1) {
                new_ident->uid = uid;
                new_ident->suid = new_ident->euid;
            }

            0;
        })
    );
}

int setresgid(process_t *process, uint32_t gid, uint32_t egid, uint32_t sgid) {
    update_identity(
        (gid == (uint32_t)-1 || gid == old_ident->gid || gid == old_ident->egid || gid == old_ident->sgid) &&
            (egid == (uint32_t)-1 || egid == old_ident->gid || egid == old_ident->egid || egid == old_ident->sgid) &&
            (sgid == (uint32_t)-1 || gid == old_ident->gid || sgid == old_ident->egid || sgid == old_ident->sgid),
        ({
            if (gid != (uint32_t)-1) new_ident->gid = gid;
            if (egid != (uint32_t)-1) new_ident->egid = egid;
            if (sgid != (uint32_t)-1) new_ident->sgid = sgid;

            0;
        })
    );
}

int setresuid(process_t *process, uint32_t uid, uint32_t euid, uint32_t suid) {
    update_identity(
        (uid == (uint32_t)-1 || uid == old_ident->uid || uid == old_ident->euid || uid == old_ident->suid) &&
            (euid == (uint32_t)-1 || euid == old_ident->uid || euid == old_ident->euid || euid == old_ident->suid) &&
            (suid == (uint32_t)-1 || uid == old_ident->uid || suid == old_ident->euid || suid == old_ident->suid),
        ({
            if (uid != (uint32_t)-1) new_ident->uid = uid;
            if (euid != (uint32_t)-1) new_ident->euid = euid;
            if (suid != (uint32_t)-1) new_ident->suid = suid;

            0;
        })
    );
}

int setgroups(process_t *process, const uint32_t *groups, size_t count) {
    update_identity(false, ({
                        uint32_t *buffer = vmalloc(sizeof(*groups) * count);
                        int error = ENOMEM;

                        if (likely(buffer)) {
                            error = user_memcpy(buffer, groups, sizeof(*groups) * count);

                            if (likely(!error)) {
                                vfree(new_ident->groups, sizeof(*new_ident->groups) * new_ident->num_groups);
                                new_ident->groups = buffer;
                                new_ident->num_groups = count;
                            } else {
                                vfree(buffer, sizeof(*groups) * count);
                            }
                        }

                        error;
                    }));
}

ident_t *ident_get(process_t *process) {
    rcu_read_lock();
    ident_t *ident = rcu_read(process->identity);
    ident_ref(ident);
    rcu_read_unlock();
    return ident;
}

relation_t get_relation(ident_t *ident, uint32_t uid, uint32_t gid, bool use_real) {
    if ((use_real ? ident->uid : ident->euid) == uid) return RELATION_OWNER;
    if ((use_real ? ident->gid : ident->egid) == gid) return RELATION_GROUP;

    for (size_t i = 0; i < ident->num_groups; i++) {
        if (ident->groups[i] == gid) return RELATION_GROUP;
    }

    return RELATION_OTHER;
}

void ident_ref(ident_t *ident) {
    ref_inc(&ident->references);
}

void ident_deref(ident_t *ident) {
    if (ref_dec(&ident->references)) {
        vfree(ident->groups, sizeof(*ident->groups) * ident->num_groups);
        vfree(ident, sizeof(*ident));
    }
}

void pid_handle_removal_and_unlock(pid_t *pid) {
    if (pid->thread == NULL && pid->process == NULL && pid->group == NULL && pid->session == NULL) {
        make_free_entry(pid->id, free_pids, 0);
        free_pids = pid->id;
        vfree(pid, sizeof(*pid));
    }

    mutex_rel(&pids_lock);
}
