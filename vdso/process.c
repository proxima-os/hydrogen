#include "hydrogen/process.h"
#include "arch/syscall.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "vdso.h"

EXPORT hydrogen_ret_t hydrogen_process_find(int id, uint32_t flags) {
    return SYSCALL2(SYSCALL_PROCESS_FIND, id, flags);
}

EXPORT hydrogen_ret_t hydrogen_process_create(uint32_t flags) {
    return SYSCALL1(SYSCALL_PROCESS_CREATE, flags);
}

EXPORT hydrogen_ret_t hydrogen_process_getppid(int process) {
    return SYSCALL1(SYSCALL_PROCESS_GETPPID, process);
}

EXPORT hydrogen_ret_t hydrogen_process_getpgid(int process) {
    return SYSCALL1(SYSCALL_PROCESS_GETPGID, process);
}

EXPORT hydrogen_ret_t hydrogen_process_getsid(int process) {
    return SYSCALL1(SYSCALL_PROCESS_GETSID, process);
}

EXPORT int hydrogen_process_setpgid(int process, int group_id) {
    return SYSCALL2(SYSCALL_PROCESS_SETPGID, process, group_id).error;
}

EXPORT hydrogen_ret_t hydrogen_process_setsid(int process) {
    return SYSCALL1(SYSCALL_PROCESS_SETSID, process);
}

EXPORT hydrogen_ret_t hydrogen_process_getgid(int process) {
    return SYSCALL1(SYSCALL_PROCESS_GETGID, process);
}

EXPORT hydrogen_ret_t hydrogen_process_getuid(int process) {
    return SYSCALL1(SYSCALL_PROCESS_GETUID, process);
}

EXPORT hydrogen_ret_t hydrogen_process_getegid(int process) {
    return SYSCALL1(SYSCALL_PROCESS_GETEGID, process);
}

EXPORT hydrogen_ret_t hydrogen_process_geteuid(int process) {
    return SYSCALL1(SYSCALL_PROCESS_GETEUID, process);
}

EXPORT int hydrogen_process_getresgid(int process, uint32_t ids[3]) {
    return SYSCALL2(SYSCALL_PROCESS_GETRESGID, process, ids).error;
}

EXPORT int hydrogen_process_getresuid(int process, uint32_t ids[3]) {
    return SYSCALL2(SYSCALL_PROCESS_GETRESUID, process, ids).error;
}

EXPORT hydrogen_ret_t hydrogen_process_getgroups(int process, uint32_t *buffer, size_t count) {
    return SYSCALL3(SYSCALL_PROCESS_GETGROUPS, process, buffer, count);
}

EXPORT int hydrogen_process_setgid(int process, uint32_t gid) {
    return SYSCALL2(SYSCALL_PROCESS_SETGID, process, gid).error;
}

EXPORT int hydrogen_process_setuid(int process, uint32_t uid) {
    return SYSCALL2(SYSCALL_PROCESS_SETUID, process, uid).error;
}

EXPORT int hydrogen_process_setegid(int process, uint32_t egid) {
    return SYSCALL2(SYSCALL_PROCESS_SETEGID, process, egid).error;
}

EXPORT int hydrogen_process_seteuid(int process, uint32_t euid) {
    return SYSCALL2(SYSCALL_PROCESS_SETEUID, process, euid).error;
}

EXPORT int hydrogen_process_setregid(int process, uint32_t rgid, uint32_t egid) {
    return SYSCALL3(SYSCALL_PROCESS_SETREGID, process, rgid, egid).error;
}

EXPORT int hydrogen_process_setreuid(int process, uint32_t ruid, uint32_t euid) {
    return SYSCALL3(SYSCALL_PROCESS_SETREUID, process, ruid, euid).error;
}

EXPORT int hydrogen_process_setresgid(int process, uint32_t rgid, uint32_t egid, uint32_t sgid) {
    return SYSCALL4(SYSCALL_PROCESS_SETRESGID, process, rgid, egid, sgid).error;
}

EXPORT int hydrogen_process_setresuid(int process, uint32_t ruid, uint32_t euid, uint32_t suid) {
    return SYSCALL4(SYSCALL_PROCESS_SETRESUID, process, ruid, euid, suid).error;
}

EXPORT int hydrogen_process_setgroups(int process, const uint32_t *groups, size_t count) {
    return SYSCALL3(SYSCALL_PROCESS_SETGROUPS, process, groups, count).error;
}

EXPORT int hydrogen_process_sigaction(
        int process,
        int signal,
        const struct __sigaction *action,
        struct __sigaction *old
) {
    return SYSCALL4(SYSCALL_PROCESS_SIGACTION, process, signal, action, old).error;
}

EXPORT int hydrogen_process_send_signal(int process, int signal) {
    return SYSCALL2(SYSCALL_PROCESS_SEND_SIGNAL, process, signal).error;
}

EXPORT int hydrogen_process_group_send_signal(int group_id, int signal) {
    return SYSCALL2(SYSCALL_PROCESS_GROUP_SEND_SIGNAL, group_id, signal).error;
}

EXPORT int hydrogen_process_sigwait(int process, __sigset_t set, __siginfo_t *info, uint64_t deadline) {
    return SYSCALL4(SYSCALL_PROCESS_SIGWAIT, process, set, info, deadline).error;
}

EXPORT void hydrogen_process_exit(int status) {
    SYSCALL1(SYSCALL_PROCESS_EXIT, status);
    UNREACHABLE();
}

EXPORT int hydrogen_process_wait(int process, unsigned int flags, __siginfo_t *info, uint64_t deadline) {
    return SYSCALL4(SYSCALL_PROCESS_WAIT, process, flags, info, deadline).error;
}

EXPORT hydrogen_ret_t hydrogen_process_wait_id(int process, unsigned int flags, __siginfo_t *info, uint64_t deadline) {
    return SYSCALL4(SYSCALL_PROCESS_WAIT_ID, process, flags, info, deadline);
}
