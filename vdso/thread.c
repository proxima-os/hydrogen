#include "hydrogen/thread.h"
#include "arch/syscall.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "vdso.h"

EXPORT _Noreturn void hydrogen_thread_exit(int status) {
    SYSCALL1(SYSCALL_THREAD_EXIT, status);
    UNREACHABLE();
}
