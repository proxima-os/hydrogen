#include "hydrogen/thread.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "syscall.h"
#include "vdso.h"

__attribute__((__noreturn__)) EXPORT void hydrogen_thread_exit(void) {
    UNUSED int ret, error;
    SYSCALL0(SYSCALL_THREAD_EXIT);
    __builtin_trap();
}
