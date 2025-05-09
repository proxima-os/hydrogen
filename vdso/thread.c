#include "hydrogen/thread.h"
#include "arch/syscall.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "vdso.h"

EXPORT int hydrogen_thread_create(int process, int vmm, int namespace, uintptr_t pc, uintptr_t sp, uint32_t flags) {
    return SYSCALL6(SYSCALL_THREAD_CREATE, process, vmm, namespace, pc, sp, flags).error;
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
