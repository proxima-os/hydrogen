#include "hydrogen/thread.h"
#include "arch/syscall.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "vdso.h"

EXPORT void hydrogen_thread_yield(void) {
    SYSCALL0(SYSCALL_THREAD_YIELD);
}

EXPORT _Noreturn void hydrogen_thread_exit(int status) {
    SYSCALL1(SYSCALL_THREAD_EXIT, status);
    UNREACHABLE();
}
