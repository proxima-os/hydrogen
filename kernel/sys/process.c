#include "hydrogen/process.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "hydrogen/handle.h"
#include "hydrogen/signal.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "proc/mutex.h"
#include "proc/process.h"
#include "proc/rcu.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "sys/process.h"
#include "sys/syscall.h"
#include "util/handle.h"
#include "util/list.h"
#include "util/object.h"
#include <stdint.h>

#define PROCESS_RIGHTS (THIS_PROCESS_RIGHTS | HYDROGEN_PROCESS_WAIT_SIGNAL)

hydrogen_ret_t hydrogen_process_find(int id, uint32_t flags) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return ret_error(EINVAL);
    if (unlikely(id == 0)) return ret_error(ESRCH);

    if (id < 0 || id == getpid(current_thread->process)) {
        return hnd_alloc(&current_thread->process->base, THIS_PROCESS_RIGHTS, flags);
    }

    process_t *proc;
    int error = resolve_process(&proc, id);
    if (unlikely(error)) return ret_error(error);

    object_rights_t rights = HYDROGEN_PROCESS_GET_IDENTITY;

    if (rcu_read(proc->parent) == current_thread->process) {
        if (!__atomic_load_n(&proc->did_exec, __ATOMIC_ACQUIRE)) rights |= HYDROGEN_PROCESS_CHANGE_GROUP;
    }

    hydrogen_ret_t ret = hnd_alloc(&proc->base, rights, flags);
    obj_deref(&proc->base);
    return ret;
}

hydrogen_ret_t hydrogen_process_create(uint32_t flags) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return ret_error(EINVAL);

    process_t *process;
    int error = proc_clone(&process);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = hnd_alloc(&process->base, PROCESS_RIGHTS, flags);
    obj_deref(&process->base);
    return ret;
}

hydrogen_ret_t hydrogen_process_getpid(int process) {
    process_t *proc;
    int error = process_or_this(&proc, process, 0);
    if (unlikely(error)) return ret_error(error);

    int id = getpid(proc);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret_integer(id);
}

hydrogen_ret_t hydrogen_process_getppid(int process) {
    process_t *proc;
    int error = process_or_this(&proc, process, 0);
    if (unlikely(error)) return ret_error(error);

    int id = getppid(proc);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret_integer(id);
}

hydrogen_ret_t hydrogen_process_getpgid(int process) {
    process_t *proc;
    int error = process_or_this(&proc, process, 0);
    if (unlikely(error)) return ret_error(error);

    int id = getpgid(proc);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret_integer(id);
}

hydrogen_ret_t hydrogen_process_getsid(int process) {
    process_t *proc;
    int error = process_or_this(&proc, process, 0);
    if (unlikely(error)) return ret_error(error);

    int id = getsid(proc);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret_integer(id);
}

int hydrogen_process_setpgid(int process, int group_id) {
    process_t *proc;
    int ret = process_or_this(&proc, process, HYDROGEN_PROCESS_CHANGE_GROUP);
    if (unlikely(ret)) return ret;

    ret = setpgid(proc, group_id);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret;
}

hydrogen_ret_t hydrogen_process_setsid(int process) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_CHANGE_SESSION);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = setsid(proc);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret;
}

hydrogen_ret_t hydrogen_process_getgid(int process) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_GET_IDENTITY);
    if (unlikely(error)) return ret_error(error);

    uint32_t id = getgid(proc);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret_integer(id);
}

hydrogen_ret_t hydrogen_process_getuid(int process) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_GET_IDENTITY);
    if (unlikely(error)) return ret_error(error);

    uint32_t id = getuid(proc);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret_integer(id);
}

hydrogen_ret_t hydrogen_process_getegid(int process) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_GET_IDENTITY);
    if (unlikely(error)) return ret_error(error);

    uint32_t id = getegid(proc);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret_integer(id);
}

hydrogen_ret_t hydrogen_process_geteuid(int process) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_GET_IDENTITY);
    if (unlikely(error)) return ret_error(error);

    uint32_t id = geteuid(proc);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret_integer(id);
}

int hydrogen_process_getresgid(int process, uint32_t ids[3]) {
    int error = verify_user_buffer((uintptr_t)ids, sizeof(*ids) * 3);
    if (unlikely(error)) return error;

    process_t *proc;
    error = process_or_this(&proc, process, HYDROGEN_PROCESS_GET_IDENTITY);
    if (unlikely(error)) return error;

    error = getresgid(proc, ids);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

int hydrogen_process_getresuid(int process, uint32_t ids[3]) {
    int error = verify_user_buffer((uintptr_t)ids, sizeof(*ids) * 3);
    if (unlikely(error)) return error;

    process_t *proc;
    error = process_or_this(&proc, process, HYDROGEN_PROCESS_GET_IDENTITY);
    if (unlikely(error)) return error;

    error = getresuid(proc, ids);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

hydrogen_ret_t hydrogen_process_getgroups(int process, uint32_t *buffer, size_t count) {
    int error = verify_user_buffer((uintptr_t)buffer, sizeof(*buffer) * count);
    if (unlikely(error)) return ret_error(error);

    process_t *proc;
    error = process_or_this(&proc, process, HYDROGEN_PROCESS_GET_IDENTITY);
    if (unlikely(error)) return ret_error(error);

    error = getgroups(proc, buffer, &count);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return RET_MAYBE(integer, error, count);
}

int hydrogen_process_setgid(int process, uint32_t gid) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_SET_IDENTITY);
    if (unlikely(error)) return error;

    error = setgid(proc, gid);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

int hydrogen_process_setuid(int process, uint32_t uid) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_SET_IDENTITY);
    if (unlikely(error)) return error;

    error = setuid(proc, uid);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

int hydrogen_process_setegid(int process, uint32_t egid) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_SET_IDENTITY);
    if (unlikely(error)) return error;

    error = setegid(proc, egid);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

int hydrogen_process_seteuid(int process, uint32_t euid) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_SET_IDENTITY);
    if (unlikely(error)) return error;

    error = seteuid(proc, euid);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

int hydrogen_process_setregid(int process, uint32_t rgid, uint32_t egid) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_SET_IDENTITY);
    if (unlikely(error)) return error;

    error = setregid(proc, rgid, egid);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

int hydrogen_process_setreuid(int process, uint32_t ruid, uint32_t euid) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_SET_IDENTITY);
    if (unlikely(error)) return error;

    error = setreuid(proc, ruid, euid);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

int hydrogen_process_setresgid(int process, uint32_t rgid, uint32_t egid, uint32_t sgid) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_SET_IDENTITY);
    if (unlikely(error)) return error;

    error = setresgid(proc, rgid, egid, sgid);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

int hydrogen_process_setresuid(int process, uint32_t ruid, uint32_t euid, uint32_t suid) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_SET_IDENTITY);
    if (unlikely(error)) return error;

    error = setresuid(proc, ruid, euid, suid);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

int hydrogen_process_setgroups(int process, const uint32_t *groups, size_t count) {
    int error = verify_user_buffer((uintptr_t)groups, sizeof(*groups) * count);
    if (unlikely(error)) return error;

    process_t *proc;
    error = process_or_this(&proc, process, HYDROGEN_PROCESS_SET_IDENTITY);
    if (unlikely(error)) return error;

    error = setgroups(proc, groups, count);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

int hydrogen_process_sigaction(int process, int signal, const struct __sigaction *action, struct __sigaction *old) {
    if (unlikely(signal < 1) || unlikely(signal >= __NSIG)) return EINVAL;

    if (action) {
        int error = verify_user_buffer((uintptr_t)action, sizeof(*action));
        if (unlikely(error)) return error;
    }

    if (old) {
        int error = verify_user_buffer((uintptr_t)old, sizeof(*action));
        if (unlikely(error)) return error;
    }

    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_CHANGE_SIGHAND);
    if (unlikely(error)) return error;

    error = sigaction(proc, signal, action, old);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

int hydrogen_process_send_signal(int process, int signal) {
    if (unlikely(signal < 0 || signal >= __NSIG)) return EINVAL;

    if (process == HYDROGEN_INVALID_HANDLE) {
        return broadcast_signal(signal);
    }

    process_t *proc;
    int error = process_or_this(&proc, process, 0);
    if (unlikely(error)) return error;

    __siginfo_t info;
    create_user_siginfo(&info, signal);

    if (unlikely(!can_send_signal(proc, &info))) {
        error = EPERM;
        goto ret;
    }

    if (signal == 0) goto ret;

    error = queue_signal(proc, &proc->sig_target, &info, 0, NULL);
ret:
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

int hydrogen_process_group_send_signal(int group_id, int signal) {
    if (unlikely(signal < 0 || signal >= __NSIG)) return EINVAL;
    if (unlikely(group_id == 0)) return ESRCH;

    pgroup_t *group;
    int error = resolve_pgroup(&group, group_id);
    if (unlikely(error)) return error;

    error = group_signal(group, signal);
    pgroup_deref(group);
    return error;
}

int hydrogen_process_sigwait(int process, __sigset_t set, __siginfo_t *info, uint64_t deadline) {
    int error = verify_user_buffer((uintptr_t)info, sizeof(*info));
    if (unlikely(error)) return error;

    process_t *proc;
    error = process_or_this(&proc, process, HYDROGEN_PROCESS_WAIT_SIGNAL);
    if (unlikely(error)) return error;

    error = sigwait(proc, set, info, deadline);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

void hydrogen_process_exit(int status) {
    process_t *proc = current_thread->process;
    __atomic_store_n(&proc->exiting, true, __ATOMIC_RELEASE);

    mutex_acq(&proc->threads_lock, 0, false);

    LIST_FOREACH(proc->threads, thread_t, process_node, thread) {
        sched_interrupt(thread, true);
    }

    proc_wait_until_single_threaded();
    mutex_rel(&proc->threads_lock);
    sched_exit(status);
}

#define WAIT_FLAGS                                                                                 \
    (HYDROGEN_PROCESS_WAIT_EXITED | HYDROGEN_PROCESS_WAIT_KILLED | HYDROGEN_PROCESS_WAIT_STOPPED | \
     HYDROGEN_PROCESS_WAIT_CONTINUED | HYDROGEN_PROCESS_WAIT_DISCARD | HYDROGEN_PROCESS_WAIT_UNQUEUE)

int hydrogen_process_wait(int process, unsigned flags, __siginfo_t *info, uint64_t deadline) {
    if (unlikely((flags & ~WAIT_FLAGS) != 0)) return EINVAL;

    int error = verify_user_buffer((uintptr_t)info, sizeof(*info));
    if (unlikely(error)) return error;

    handle_data_t data;
    error = hnd_resolve(&data, process, OBJECT_PROCESS, HYDROGEN_PROCESS_WAIT_STATUS);
    if (unlikely(error)) return error;

    error = proc_wait((process_t *)data.object, flags, info, deadline);
    obj_deref(data.object);
    return error;
}

hydrogen_ret_t hydrogen_process_wait_id(int process, unsigned flags, __siginfo_t *info, uint64_t deadline) {
    if (unlikely(process < 0)) return ret_error(EINVAL);
    if (unlikely((flags & ~WAIT_FLAGS) != 0)) return ret_error(EINVAL);

    int error = verify_user_buffer((uintptr_t)info, sizeof(*info));
    if (unlikely(error)) return ret_error(error);

    return proc_waitid(process, flags, info, deadline);
}

int hydrogen_process_get_cpu_time(hydrogen_cpu_time_t *time) {
    int error = verify_user_buffer((uintptr_t)time, sizeof(*time));
    if (unlikely(error)) return error;

    process_t *process = current_thread->process;
    hydrogen_cpu_time_t value = {
            .user_time = __atomic_load_n(&process->user_time, __ATOMIC_RELAXED),
            .kernel_time = __atomic_load_n(&process->kern_time, __ATOMIC_RELAXED),
            .child_user_time = __atomic_load_n(&process->child_user_time, __ATOMIC_RELAXED),
            .child_kernel_time = __atomic_load_n(&process->child_kern_time, __ATOMIC_RELAXED),
    };
    return user_memcpy(time, &value, sizeof(*time));
}
