#include "kernel/thread.h"
#include "arch/syscall.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "vdso.h"
#include <hydrogen/thread.h>
#include <hydrogen/types.h>

EXPORT hydrogen_ret_t
hydrogen_thread_create(int process, int vmm, int namespace, uintptr_t pc, uintptr_t sp, uint32_t flags) {
    return SYSCALL6(SYSCALL_THREAD_CREATE, process, vmm, namespace, pc, sp, flags);
}

EXPORT hydrogen_ret_t hydrogen_thread_exec(
    int process,
    int namespace,
    int image,
    size_t argc,
    const hydrogen_string_t *argv,
    size_t envc,
    const hydrogen_string_t *envp,
    uint32_t flags
) {
    exec_syscall_args_t args = {argv, envp, argc, envc};
    return SYSCALL5(SYSCALL_THREAD_EXEC, process, namespace, image, &args, flags);
}

EXPORT hydrogen_ret_t hydrogen_thread_clone(int process, int vmm, int namespace, uint32_t flags) {
    return SYSCALL4(SYSCALL_THREAD_CLONE, process, vmm, namespace, flags);
}

EXPORT int hydrogen_thread_reinit(int vmm, int namespace, uintptr_t pc, uintptr_t sp) {
    return SYSCALL4(SYSCALL_THREAD_REINIT, vmm, namespace, pc, sp).error;
}

EXPORT void hydrogen_thread_yield(void) {
    SYSCALL0(SYSCALL_THREAD_YIELD);
}

EXPORT _Noreturn void hydrogen_thread_exit(int status) {
    SYSCALL1(SYSCALL_THREAD_EXIT, status);
    UNREACHABLE();
}

EXPORT int hydrogen_thread_sleep(uint64_t deadline) {
    return SYSCALL1(SYSCALL_THREAD_SLEEP, deadline).error;
}

EXPORT int hydrogen_thread_sigmask(int how, const __sigset_t *set, __sigset_t *oset) {
    return SYSCALL3(SYSCALL_THREAD_SIGMASK, how, set, oset).error;
}

EXPORT int hydrogen_thread_sigaltstack(const __stack_t *ss, __stack_t *oss) {
    return SYSCALL2(SYSCALL_THREAD_SIGALTSTACK, ss, oss).error;
}

EXPORT __sigset_t hydrogen_thread_sigpending(void) {
    return SYSCALL0(SYSCALL_THREAD_SIGPENDING).integer;
}

EXPORT int hydrogen_thread_sigsuspend(__sigset_t mask) {
    return SYSCALL1(SYSCALL_THREAD_SIGSUSPEND, mask).integer;
}

EXPORT int hydrogen_thread_send_signal(int thread, int signal) {
    return SYSCALL2(SYSCALL_THREAD_SEND_SIGNAL, thread, signal).error;
}

EXPORT hydrogen_ret_t hydrogen_thread_get_id(int thread) {
    return SYSCALL1(SYSCALL_THREAD_GET_ID, thread);
}

EXPORT hydrogen_ret_t hydrogen_thread_find(int process, int thread_id, uint32_t flags) {
    return SYSCALL3(SYSCALL_THREAD_FIND, process, thread_id, flags);
}

EXPORT int hydrogen_thread_get_cpu_time(hydrogen_cpu_time_t *time) {
    return SYSCALL1(SYSCALL_THREAD_GET_CPU_TIME, time).error;
}
