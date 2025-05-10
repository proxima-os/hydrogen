#include "kernel/x86_64/signal.h"
#include "arch/syscall.h"
#include "kernel/x86_64/syscall.h"

int x86_64_sigreturn(uintptr_t ctx) {
    SYSCALL1(X86_64_SYSCALL_SIGRETURN, ctx);
    __builtin_trap();
}
