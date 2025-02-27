#include "hydrogen/thread.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "syscall.h"

__attribute__((__noreturn__)) void hydrogen_thread_exit(void) {
    UNUSED int ret, error;
    SYSCALL0(SYSCALL_THREAD_EXIT);
    __builtin_unreachable();
}
