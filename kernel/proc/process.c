#include "proc/process.h"
#include "arch/pmap.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "hydrogen/eventqueue.h"
#include "hydrogen/signal.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "proc/mutex.h"
#include "proc/rcu.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "sections.h"
#include "string.h"
#include "util/eventqueue.h"
#include "util/list.h"
#include "util/object.h"
#include "util/panic.h"
#include "util/refcount.h"
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

process_t kernel_process;
process_t *init_process;

static pid_t **pids;
static uint64_t *pids_map;
static size_t pids_capacity;
static size_t pids_search_start;
static mutex_t pids_update_lock;

static pgroup_t kernel_group = {.references = REF_INIT(1)};
static session_t kernel_session = {.references = REF_INIT(1)};

static size_t get_free_pid(void) {
    for (size_t i = pids_search_start; i < pids_capacity; i += 64) {
        uint64_t value = pids_map[i / 64];
        if (value == UINT64_MAX) continue;
        return i + __builtin_ctzll(~value);
    }

    for (size_t i = 0; i < pids_search_start; i += 64) {
        uint64_t value = pids_map[i / 64];
        if (value == UINT64_MAX) continue;
        return i + __builtin_ctzll(~value);
    }

    return pids_capacity;
}

static size_t get_map_offset(size_t capacity) {
    return (capacity * sizeof(*pids) + (_Alignof(uint64_t) - 1)) & ~(_Alignof(uint64_t) - 1);
}

static size_t get_map_size(size_t capacity) {
    return (capacity + 63) / 64 * sizeof(*pids_map);
}

INIT_TEXT static void init_pids(void) {
    pids_capacity = 8;

    size_t map_offs = get_map_offset(pids_capacity);
    size_t map_size = get_map_size(pids_capacity);
    void *buffer = vmalloc(map_offs + map_size);
    if (unlikely(!buffer)) panic("failed to allocate pid table");
    memset(buffer, 0, map_offs + map_size);

    pids = buffer;
    pids_map = buffer + map_offs;
}

static bool expand_pids(void) {
    ASSERT(pids_capacity != 0);
    size_t new_cap = pids_capacity * 2;

    size_t map_offs = get_map_offset(new_cap);
    size_t map_size = get_map_size(new_cap);
    void *buffer = vmalloc(map_offs + map_size);
    if (unlikely(!buffer)) return false;

    pid_t **new_pids = buffer;
    uint64_t *new_map = buffer + map_offs;

    memcpy(new_pids, pids, pids_capacity * sizeof(*pids));
    memset(&new_pids[pids_capacity], 0, (new_cap - pids_capacity) * sizeof(*pids));

    size_t old_size = get_map_size(pids_capacity);
    memcpy(new_map, pids_map, old_size);
    memset((void *)new_map + old_size, 0, map_size - old_size);

    pid_t **old_pids = pids;
    size_t old_pids_size = get_map_size(pids_capacity) + old_size;

    pids_map = new_map;
    rcu_write(pids, new_pids);
    __atomic_store_n(&pids_capacity, new_cap, __ATOMIC_RELEASE);
    rcu_sync();
    vfree(old_pids, old_pids_size);

    return true;
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

    mutex_acq(&pids_update_lock, 0, false);

    size_t id = get_free_pid();
    if (id > (size_t)INT_MAX) {
        mutex_rel(&pids_update_lock);
        return EAGAIN;
    }

    if (id >= pids_capacity && unlikely(!expand_pids())) {
        mutex_rel(&pids_update_lock);
        return ENOMEM;
    }

    pid->id = id;

    pids_map[id / 64] |= 1ull << (id % 64);
    pids_search_start = id - (id % 64);
    rcu_write(pids[id], pid);
    mutex_rel(&pids_update_lock);
    return 0;
}

static void process_free(object_t *ptr) {
    process_t *process = (process_t *)ptr;
    ASSERT(process != &kernel_process);

    pid_t *pid = process->pid;
    mutex_acq(&pid->remove_lock, 0, false);
    rcu_write(pid->process, NULL);
    pid_handle_removal_and_unlock(pid);

    pgroup_deref(process->group);
    ident_deref(process->identity);

    signal_cleanup(&process->sig_target);
    vfree(process, sizeof(*process));
}

static int process_event_add(object_t *ptr, active_event_t *event) {
    process_t *self = (process_t *)ptr;

    switch (event->source.type) {
    case HYDROGEN_EVENT_SIGNAL_PENDING: return event_source_add(&self->sig_target.event_source, event);
    default: return EINVAL;
    }
}

static bool process_event_get(object_t *ptr, active_event_t *event, hydrogen_event_t *out) {
    process_t *self = (process_t *)ptr;

    switch (event->source.type) {
    case HYDROGEN_EVENT_SIGNAL_PENDING:
        out->data = __atomic_load_n(&self->sig_target.queue_map, __ATOMIC_ACQUIRE) & event->source.data;
        return out->data != 0;
    default: UNREACHABLE();
    }
}

static void process_event_del(object_t *ptr, active_event_t *event) {
    process_t *self = (process_t *)ptr;

    switch (event->source.type) {
    case HYDROGEN_EVENT_SIGNAL_PENDING: return event_source_del(&self->sig_target.event_source, event);
    default: UNREACHABLE();
    }
}

static const object_ops_t process_ops = {
        .free = process_free,
        .event_add = process_event_add,
        .event_get = process_event_get,
        .event_del = process_event_del,
};

INIT_TEXT void proc_init(void) {
    kernel_process.base.ops = &process_ops;
    obj_init(&kernel_process.base, OBJECT_PROCESS);
    init_pids();

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

int resolve_thread(struct thread **out, int tid) {
    if (tid < 0) return EINVAL;
    if ((size_t)tid >= __atomic_load_n(&pids_capacity, __ATOMIC_ACQUIRE)) return ESRCH;

    rcu_state_t state = rcu_read_lock();

    pid_t *pid = rcu_read(rcu_read(pids)[tid]);

    if (unlikely(!pid)) {
        rcu_read_unlock(state);
        return ESRCH;
    }

    thread_t *thread = rcu_read(pid->thread);

    if (unlikely(!thread)) {
        rcu_read_unlock(state);
        return ESRCH;
    }

    obj_ref(&thread->base);
    rcu_read_unlock(state);
    *out = thread;
    return 0;
}

int resolve_process(process_t **out, int pid) {
    if (pid < 0) return EINVAL;
    if ((size_t)pid >= __atomic_load_n(&pids_capacity, __ATOMIC_ACQUIRE)) return ESRCH;

    rcu_state_t state = rcu_read_lock();

    pid_t *ppid = rcu_read(rcu_read(pids)[pid]);

    if (unlikely(!ppid)) {
        rcu_read_unlock(state);
        return ESRCH;
    }

    process_t *process = rcu_read(ppid->process);

    if (unlikely(!process)) {
        rcu_read_unlock(state);
        return ESRCH;
    }

    obj_ref(&process->base);
    rcu_read_unlock(state);
    *out = process;
    return 0;
}

int resolve_pgroup(pgroup_t **out, int pgid) {
    if (pgid < 0) return EINVAL;
    if ((size_t)pgid >= __atomic_load_n(&pids_capacity, __ATOMIC_ACQUIRE)) return ESRCH;

    rcu_state_t state = rcu_read_lock();

    pid_t *pid = rcu_read(rcu_read(pids)[pgid]);

    if (unlikely(!pid)) {
        rcu_read_unlock(state);
        return ESRCH;
    }

    pgroup_t *group = rcu_read(pid->group);

    if (unlikely(!group)) {
        rcu_read_unlock(state);
        return ESRCH;
    }

    pgroup_ref(group);
    rcu_read_unlock(state);
    *out = group;
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

    int error = allocate_pid(process, NULL);
    if (unlikely(error)) {
        ident_deref(process->identity);
        vfree(process, sizeof(*process));
        return error;
    }

    obj_ref(&process->parent->base);
    mutex_acq(&process->parent->children_lock, 0, false);
    list_insert_tail(&process->parent->children, &process->parent_node);
    mutex_rel(&process->parent->children_lock);

    rcu_state_t state = rcu_read_lock();
    pgroup_t *group = current_thread->process->group;
    pgroup_ref(group);
    rcu_read_unlock(state);

    process->group = group;
    mutex_acq(&group->members_lock, 0, false);
    list_insert_tail(&group->members, &process->group_node);
    mutex_rel(&group->members_lock);

    *out = process;
    return 0;
}

int proc_thread_create(process_t *process, struct thread *thread) {
    mutex_acq(&process->threads_lock, 0, false);

    if (process->exiting) {
        mutex_rel(&process->threads_lock);
        return EINVAL;
    }

    if (list_empty(&process->threads)) {
        thread->pid = process->pid;
        rcu_write(thread->pid->thread, thread);
    } else if (process != current_thread->process) {
        mutex_rel(&process->threads_lock);
        return EPERM;
    } else if (process != &kernel_process) {
        int error = allocate_pid(NULL, thread);

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
        rcu_state_t state = rcu_read_lock();
        process_t *parent = rcu_read(process->parent);
        obj_ref(&parent->base);
        rcu_read_unlock(state);

        mutex_acq(&parent->children_lock, 0, false);

        state = rcu_read_lock();
        bool ok = rcu_read(process->parent) == parent;
        rcu_read_unlock(state);

        if (ok) return parent;

        mutex_rel(&parent->children_lock);
        obj_deref(&parent->base);
    }
}

static void reap_process(process_t *process) {
    process_t *parent = get_parent_with_locked_children(process);
    list_remove(&parent->children, &process->parent_node);
    mutex_rel(&parent->children_lock);

    obj_deref_n(&parent->base, 2); // ref from get_parent_with_locked_children + process->parent
}

static void reparent_children(process_t *process) {
    ASSERT(init_process != NULL);

    mutex_acq(&process->children_lock, 0, false);

    for (;;) {
        process_t *child = LIST_REMOVE_HEAD(process->children, process_t, parent_node);
        if (!child) break;

        mutex_acq(&init_process->children_lock, 0, false);
        obj_deref(&process->base);
        obj_ref(&init_process->base);
        list_insert_tail(&init_process->children, &child->parent_node);
        rcu_write(child->parent, init_process);
        mutex_rel(&init_process->children_lock);
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

static void handle_process_exit(process_t *process) {
    ASSERT(process != &kernel_process);
    if (process == init_process) panic("attempted to kill init");

    reparent_children(process);
    leave_group(process->group, process);

    // TODO: For now, behave as if the parent's SIGCHLD handler has SA_NOCLDWAIT.
    // In the future, this should send a SIGCHLD and, if SA_NOCLDWAIT isn't set,
    // make wait information available.
    reap_process(process);
}

void proc_thread_exit(process_t *process, struct thread *thread) {
    mutex_acq(&process->threads_lock, 0, false);
    list_remove(&process->threads, &thread->process_node);

    bool proc_exit = list_empty(&process->threads);

    if (!proc_exit && process->threads.head == process->threads.tail && process->singlethreaded_handler != NULL) {
        sched_wake(process->singlethreaded_handler);
    }

    mutex_rel(&process->threads_lock);
    if (proc_exit) handle_process_exit(process);
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
                (new_act.__func.__handler != __SIG_IGN && (uintptr_t)new_act.__func.__handler > arch_pt_max_user_addr()
                )) {
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

        queued_signal_t *sig = get_queued_signal(&current_thread->sig_target, set);

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

    queued_signal_t *sig = get_queued_signal(&process->sig_target, set);

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
    rcu_state_t state = rcu_read_lock();

    if (info->__signo == __SIGCONT &&
        rcu_read(current_thread->process->group)->session == rcu_read(process->group->session)) {
        rcu_read_unlock(state);
        return true;
    }

    ident_t *rx_ident = rcu_read(process->identity);

    if (info->__data.__user_or_sigchld.__uid == rx_ident->uid ||
        info->__data.__user_or_sigchld.__uid == rx_ident->suid) {
        rcu_read_unlock(state);
        return true;
    }

    ident_t *tx_ident = rcu_read(current_thread->process->identity);

    if (tx_ident->euid == 0) {
        rcu_read_unlock(state);
        return true;
    }

    bool ok = tx_ident->euid == rx_ident->uid || tx_ident->euid == rx_ident->suid;
    rcu_read_unlock(state);
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

    mutex_acq(&pids_update_lock, 0, false);

    uint64_t *bitmap = pids_map;

    for (size_t i = 0; i < pids_capacity; i += 64) {
        uint64_t bmval = *bitmap++;
        if (!bmval) continue;

        pid_t **pid = &pids[i];

        do {
            size_t extra = __builtin_ctzll(bmval);
            bmval >>= extra;
            pid += extra;

            process_t *proc = pid[0]->process;

            if (proc && proc != current_thread->process) {
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

            bmval &= ~1;
        } while (bmval);
    }

done:
    mutex_rel(&pids_update_lock);
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
    if (ref_dec(&group->references) == 1) {
        ASSERT(group != &kernel_group);

        pid_t *pid = group->pid;
        mutex_acq(&pid->remove_lock, 0, false);
        rcu_write(pid->group, NULL);
        pid_handle_removal_and_unlock(pid);

        session_deref(group->session);
        vfree(group, sizeof(*group));
    }
}

void session_ref(session_t *session) {
    ref_inc(&session->references);
}

void session_deref(session_t *session) {
    if (ref_dec(&session->references)) {
        ASSERT(session != &kernel_session);

        pid_t *pid = session->pid;
        mutex_acq(&pid->remove_lock, 0, false);
        rcu_write(pid->session, NULL);
        pid_handle_removal_and_unlock(pid);

        vfree(session, sizeof(*session));
    }
}

int getpid(process_t *process) {
    return process->pid->id;
}

int getppid(process_t *process) {
    rcu_state_t state = rcu_read_lock();
    int id = rcu_read(process->parent)->pid->id;
    rcu_read_unlock(state);
    return id;
}

int getpgid(process_t *process) {
    rcu_state_t state = rcu_read_lock();
    int id = rcu_read(process->group)->pid->id;
    rcu_read_unlock(state);
    return id;
}

int getsid(process_t *process) {
    rcu_state_t state = rcu_read_lock();
    int id = rcu_read(process->group)->session->pid->id;
    rcu_read_unlock(state);
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

    rcu_state_t state = rcu_read_lock();
    session_t *own_session = rcu_read(current_thread->process->group)->session;
    session_ref(own_session);
    rcu_read_unlock(state);

    mutex_acq(&process->group_update_lock, 0, false);
    pgroup_t *old_group = process->group;

    int error = EPERM;
    if (unlikely(old_group->session->pid == process->pid)) goto err;
    if (unlikely(old_group->session != own_session)) goto err;

    pgroup_t *new_group;
    bool created = false;

    if (pgid == 0 || pgid == process->pid->id) {
        if (process->pid->group) {
            new_group = process->pid->group;

            error = 0;
            if (new_group == old_group) goto err;

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
            created = true;
        }
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

    do_leave_group(old_group, process);
    list_insert_tail(&new_group->members, &process->group_node);
    do_unlock_two(old_group, new_group);

    if (created) rcu_write(new_group->pid->group, new_group);
    rcu_write(process->group, new_group);
    mutex_rel(&process->group_update_lock);
    session_deref(own_session);
    rcu_sync();
    pgroup_deref(old_group);
    return 0;

err:
    mutex_rel(&process->group_update_lock);
    session_deref(own_session);
    return error;
}

hydrogen_ret_t setsid(process_t *process) {
    mutex_acq(&process->group_update_lock, 0, false);

    if (unlikely(process->pid->group != NULL)) {
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
    leave_group(old_group, process);

    list_insert_tail(&group->members, &process->group_node);
    rcu_write(group->pid->session, session);
    rcu_write(group->pid->group, group);
    rcu_write(process->group, group);
    mutex_rel(&process->group_update_lock);
    rcu_sync();
    pgroup_deref(old_group);
    return ret_integer(process->pid->id);
}

uint32_t getgid(process_t *process) {
    rcu_state_t state = rcu_read_lock();
    uint32_t gid = rcu_read(process->identity)->gid;
    rcu_read_unlock(state);
    return gid;
}

uint32_t getuid(process_t *process) {
    rcu_state_t state = rcu_read_lock();
    uint32_t uid = rcu_read(process->identity)->uid;
    rcu_read_unlock(state);
    return uid;
}

uint32_t getegid(process_t *process) {
    rcu_state_t state = rcu_read_lock();
    uint32_t egid = rcu_read(process->identity)->egid;
    rcu_read_unlock(state);
    return egid;
}

uint32_t geteuid(process_t *process) {
    rcu_state_t state = rcu_read_lock();
    uint32_t euid = rcu_read(process->identity)->euid;
    rcu_read_unlock(state);
    return euid;
}

int getresgid(process_t *process, uint32_t gids[3]) {
    uint32_t src[3];

    rcu_state_t state = rcu_read_lock();
    ident_t *ident = rcu_read(process->identity);
    src[0] = ident->gid;
    src[1] = ident->egid;
    src[2] = ident->sgid;
    rcu_read_unlock(state);

    return user_memcpy(gids, src, sizeof(src));
}

int getresuid(process_t *process, uint32_t uids[3]) {
    uint32_t src[3];

    rcu_state_t state = rcu_read_lock();
    ident_t *ident = rcu_read(process->identity);
    src[0] = ident->uid;
    src[1] = ident->euid;
    src[2] = ident->suid;
    rcu_read_unlock(state);

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

static ident_t *clone_ident(ident_t *src) {
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
        ident_t *new_ident = clone_ident(old_ident);      \
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
            (gid == (uint32_t)-1 || gid == old_ident->gid || gid == old_ident->sgid
            ) && (egid == (uint32_t)-1 || egid == old_ident->gid || egid == old_ident->egid || egid == old_ident->sgid),
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
            (uid == (uint32_t)-1 || uid == old_ident->uid || uid == old_ident->suid
            ) && (euid == (uint32_t)-1 || euid == old_ident->uid || euid == old_ident->euid || euid == old_ident->suid),
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
                    (egid == (uint32_t)-1 || egid == old_ident->gid || egid == old_ident->egid ||
                     egid == old_ident->sgid) &&
                    (sgid == (uint32_t)-1 || gid == old_ident->gid || sgid == old_ident->egid || sgid == old_ident->sgid
                    ),
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
                    (euid == (uint32_t)-1 || euid == old_ident->uid || euid == old_ident->euid ||
                     euid == old_ident->suid) &&
                    (suid == (uint32_t)-1 || uid == old_ident->uid || suid == old_ident->euid || suid == old_ident->suid
                    ),
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
    rcu_state_t state = rcu_read_lock();
    ident_t *ident = rcu_read(process->identity);
    ident_ref(ident);
    rcu_read_unlock(state);
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
    if (ref_dec(&ident->references) == 1) {
        vfree(ident->groups, sizeof(*ident->groups) * ident->num_groups);
        vfree(ident, sizeof(*ident));
    }
}

void pid_handle_removal_and_unlock(pid_t *pid) {
    if (pid->thread == NULL && pid->process == NULL && pid->group == NULL) {
        mutex_acq(&pids_update_lock, 0, false);
        pids_map[pid->id / 64] &= ~(1ull << pid->id % 64);
        rcu_write(pids[pid->id], NULL);
        mutex_rel(&pids_update_lock);
        rcu_sync();
        vfree(pid, sizeof(*pid));
    } else {
        mutex_rel(&pid->remove_lock);
        rcu_sync();
    }
}
