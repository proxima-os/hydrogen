#include "x86_64/syscall.h"
#include "arch/context.h"
#include "arch/irq.h"
#include "kernel/compiler.h"
#include "kernel/types.h"
#include "sections.h"
#include "sys/syscall.h"
#include "sys/transition.h"
#include "x86_64/cpu.h"
#include "x86_64/msr.h"
#include <stddef.h>
#include <stdint.h>

_Static_assert(X86_64_KERN_CS + 8 == X86_64_KERN_DS, "GDT layout incompatible with syscall");
_Static_assert(X86_64_USER_DS + 8 == X86_64_USER_CS, "GDT layout incompatible with syscall");
_Static_assert((X86_64_USER_DS & 3) == 3, "User segment selectors do not have RPL 3");

extern const void x86_64_syscall_entry;

INIT_TEXT void x86_64_syscall_init_local(void) {
    x86_64_wrmsr(X86_64_MSR_STAR, ((uint64_t)(X86_64_USER_DS - 8) << 48) | ((uint64_t)X86_64_KERN_CS << 32));
    x86_64_wrmsr(X86_64_MSR_LSTAR, (uintptr_t)&x86_64_syscall_entry);
    x86_64_wrmsr(X86_64_MSR_FMASK, 0x40600); // Clear AC, DF, and IF on entry
}

static void do_arch_syscall(ssize_t id, size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5) {
    // arch-specific syscalls would be checked for and dispatched here

    do_syscall(id, a0, a1, a2, a3, a4, a5);
}

USED void x86_64_syscall_dispatch(arch_context_t *context) {
    context->cs = X86_64_USER_CS;
    context->ss = X86_64_USER_DS;
    enter_from_user_mode(context);
    enable_irq();

    if (prepare_syscall(context->rip)) {
        do_arch_syscall(context->rax, context->rdi, context->rsi, context->rdx, context->r10, context->r8, context->r9);
    }

    exit_to_user_mode();
}
