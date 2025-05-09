#include "hydrogen/process.h"
#include "cpu/cpudata.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "proc/process.h"
#include "proc/rcu.h"
#include "sys/process.h"
#include "sys/syscall.h"
#include "util/handle.h"
#include "util/object.h"
#include <stdint.h>

#define PROCESS_RIGHTS THIS_PROCESS_RIGHTS

int hydrogen_process_find(int id, uint32_t flags) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return -EINVAL;
    if (unlikely(id == 0)) return -ESRCH;

    if (id == HYDROGEN_THIS_PROCESS || id == getpid(current_thread->process)) {
        return hnd_alloc(&current_thread->process->base, PROCESS_RIGHTS, flags);
    }

    process_t *proc;
    int ret = -resolve_process(&proc, id);
    if (unlikely(ret)) return ret;

    object_rights_t rights = HYDROGEN_PROCESS_GET_IDENTITY;

    if (rcu_read(proc->parent) == current_thread->process) {
        if (!__atomic_load_n(&proc->did_exec, __ATOMIC_ACQUIRE)) rights |= HYDROGEN_PROCESS_CHANGE_GROUP;
    }

    ret = hnd_alloc(&proc->base, rights, flags);
    obj_deref(&proc->base);
    return ret;
}

int hydrogen_process_create(uint32_t flags) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return -EINVAL;

    process_t *process;
    int ret = -proc_clone(&process);
    if (unlikely(ret)) return ret;

    ret = hnd_alloc(&process->base, PROCESS_RIGHTS, flags);
    obj_deref(&process->base);
    return ret;
}

int hydrogen_process_getpid(int process) {
    process_t *proc;
    int ret = -process_or_this(&proc, process, 0);
    if (unlikely(ret)) return ret;

    ret = getpid(proc);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret;
}

int hydrogen_process_getppid(int process) {
    process_t *proc;
    int ret = -process_or_this(&proc, process, 0);
    if (unlikely(ret)) return ret;

    ret = getppid(proc);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret;
}

int hydrogen_process_getpgid(int process) {
    process_t *proc;
    int ret = -process_or_this(&proc, process, 0);
    if (unlikely(ret)) return ret;

    ret = getpgid(proc);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret;
}

int hydrogen_process_getsid(int process) {
    process_t *proc;
    int ret = -process_or_this(&proc, process, 0);
    if (unlikely(ret)) return ret;

    ret = getsid(proc);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret;
}

int hydrogen_process_setpgid(int process, int group_id) {
    process_t *proc;
    int ret = process_or_this(&proc, process, HYDROGEN_PROCESS_CHANGE_GROUP);
    if (unlikely(ret)) return ret;

    ret = setpgid(proc, group_id);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret;
}

int hydrogen_process_setsid(int process) {
    process_t *proc;
    int ret = -process_or_this(&proc, process, HYDROGEN_PROCESS_CHANGE_SESSION);
    if (unlikely(ret)) return ret;

    ret = setsid(proc);
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
