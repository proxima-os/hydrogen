#include "proc/sched.h"
#include "arch/stack.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "x86_64/msr.h"
#include "x86_64/segreg.h"
#include "x86_64/xsave.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t rbx;
    size_t rbp;
    size_t r12;
    size_t r13;
    size_t r14;
    size_t r15;
    size_t rip;
} thread_frame_t;

extern size_t *x86_64_switch_thread(size_t *old_rsp, size_t new_rsp);
extern const void x86_64_thread_entry;

thread_t *arch_switch_thread(thread_t *from, thread_t *to) {
    this_cpu_write_tl(arch.tss.rsp[0], (uintptr_t)to->stack + KERNEL_STACK_SIZE);

    if (from->user_thread) {
        x86_64_xsave_save(from->arch.xsave);
        from->arch.ds = x86_64_read_ds();
        from->arch.es = x86_64_read_es();
        from->arch.fs = x86_64_read_fs();
        from->arch.gs = x86_64_read_gs();
    }

    if (to->user_thread) {
        x86_64_xsave_restore(to->arch.xsave);
        x86_64_write_ds(to->arch.ds);
        x86_64_write_es(to->arch.es);
        x86_64_write_fs(to->arch.fs);

        if (to->arch.gs != x86_64_read_gs()) {
            uint64_t cur = (uintptr_t)get_current_cpu();
            x86_64_write_gs(to->arch.gs);
            x86_64_wrmsr(X86_64_MSR_GS_BASE, cur);
        }

        x86_64_wrmsr(X86_64_MSR_FS_BASE, to->arch.fs_base);
        x86_64_wrmsr(X86_64_MSR_KERNEL_GS_BASE, to->arch.gs_base);
    }

    return CONTAINER(thread_t, arch.rsp, x86_64_switch_thread(&from->arch.rsp, to->arch.rsp));
}

int arch_init_thread(arch_thread_t *thread, void (*func)(void *), void *ctx, void *stack, unsigned flags) {
    stack += KERNEL_STACK_SIZE;

    thread_frame_t *frame = stack;
    frame -= 1;
    frame->rbx = (uintptr_t)func;
    frame->r12 = (uintptr_t)ctx;
    frame->rip = (uintptr_t)&x86_64_thread_entry;

    thread->rsp = (uintptr_t)frame;

    if (flags & THREAD_USER) {
        thread->xsave = x86_64_xsave_alloc();
        if (unlikely(!thread->xsave)) return ENOMEM;

        thread->ds = x86_64_read_ds();
        thread->es = x86_64_read_es();
        thread->fs = x86_64_read_fs();
        thread->gs = x86_64_read_gs();
        thread->fs_base = x86_64_rdmsr(X86_64_MSR_FS_BASE);
        thread->gs_base = x86_64_rdmsr(X86_64_MSR_KERNEL_GS_BASE);
    }

    return 0;
}

_Noreturn void x86_64_init_thread(size_t *old_rsp, void (*func)(void *), void *ctx) {
    sched_init_thread(CONTAINER(thread_t, arch.rsp, old_rsp), func, ctx);
}

void arch_reap_thread(arch_thread_t *thread) {
    if (thread->xsave != NULL) {
        x86_64_xsave_free(thread->xsave);
    }
}
