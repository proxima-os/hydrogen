#include "sys/transition.h"
#include "arch/context.h"
#include "arch/irq.h"
#include "arch/pmap.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "hydrogen/signal.h"
#include "kernel/compiler.h"
#include "proc/sched.h"
#include "string.h"
#include "sys/syscall.h"
#include "sys/vdso.h"
#include "x86_64/cpu.h"
#include "x86_64/idt.h"
#include "x86_64/msr.h"
#include "x86_64/segreg.h"
#include "x86_64/xsave.h"
#include <stddef.h>
#include <stdint.h>

_Noreturn void arch_enter_user_mode(uintptr_t pc, uintptr_t sp) {
    ASSERT(current_thread->user_thread);
    x86_64_xsave_reset(current_thread->arch.xsave);

    arch_context_t context = {
            .rip = pc,
            .cs = X86_64_USER_CS,
            .rflags = 0x200,
            .rsp = sp,
            .ss = X86_64_USER_DS,
    };

    irq_state_t state = save_disable_irq();
    cpu_t *cpu = get_current_cpu();

    x86_64_write_ds(0);
    x86_64_write_es(0);
    x86_64_write_fs(0);
    x86_64_write_gs(0);
    x86_64_wrmsr(X86_64_MSR_FS_BASE, 0);
    x86_64_wrmsr(X86_64_MSR_GS_BASE, (uintptr_t)cpu);
    x86_64_wrmsr(X86_64_MSR_KERNEL_GS_BASE, 0);

    restore_irq(state);
    arch_enter_user_mode_context(&context);
}

_Noreturn void arch_enter_user_mode_init(uintptr_t pc, uintptr_t stack_base, size_t stack_size) {
    arch_enter_user_mode(pc, stack_base + stack_size);
}

_Noreturn void arch_enter_user_mode_context(arch_context_t *context) {
    ASSERT(current_thread->user_thread);
    current_thread->user_ctx = context;
    exit_to_user_mode(-1);
    x86_64_jump_to_context(context);
}

typedef struct {
    __siginfo_t info;
    __ucontext_t context;
} signal_frame_t;

int arch_setup_context_for_signal(struct __sigaction *handler, __siginfo_t *info, __stack_t *stack) {
    uintptr_t rsp = current_thread->user_ctx->rsp - 128;

    if (stack != NULL) {
        rsp = (uintptr_t)current_thread->sig_stack.__pointer + current_thread->sig_stack.__size;
    }

    x86_64_xsave_save(current_thread->arch.xsave);

    uintptr_t xsave_start = (rsp - x86_64_xsave_size) & ~63;
    uintptr_t frame_start = (xsave_start - sizeof(signal_frame_t)) & ~16;

    int error = user_memcpy((void *)xsave_start, current_thread->arch.xsave, x86_64_xsave_size);
    if (unlikely(error)) return error;

    signal_frame_t frame = {
            .info = *info,
            .context.__link = NULL,
            .context.__mcontext.__rax = current_thread->user_ctx->rax,
            .context.__mcontext.__rbx = current_thread->user_ctx->rbx,
            .context.__mcontext.__rcx = current_thread->user_ctx->rcx,
            .context.__mcontext.__rdx = current_thread->user_ctx->rdx,
            .context.__mcontext.__rsi = current_thread->user_ctx->rsi,
            .context.__mcontext.__rdi = current_thread->user_ctx->rdi,
            .context.__mcontext.__rbp = current_thread->user_ctx->rbp,
            .context.__mcontext.__rsp = current_thread->user_ctx->rsp,
            .context.__mcontext.__r8 = current_thread->user_ctx->r8,
            .context.__mcontext.__r9 = current_thread->user_ctx->r9,
            .context.__mcontext.__r10 = current_thread->user_ctx->r10,
            .context.__mcontext.__r11 = current_thread->user_ctx->r11,
            .context.__mcontext.__r12 = current_thread->user_ctx->r12,
            .context.__mcontext.__r13 = current_thread->user_ctx->r13,
            .context.__mcontext.__r14 = current_thread->user_ctx->r14,
            .context.__mcontext.__r15 = current_thread->user_ctx->r15,
            .context.__mcontext.__rip = current_thread->user_ctx->rip,
            .context.__mcontext.__rflags = current_thread->user_ctx->rflags,
            .context.__mcontext.__xsave_area = (void *)xsave_start,
            .context.__mask = current_thread->sig_mask,
            .context.__stack = current_thread->sig_stack,
    };

    error = user_memcpy((void *)frame_start, &frame, sizeof(frame));
    if (unlikely(error)) return error;

    uintptr_t return_address = __atomic_load_n(&current_thread->vmm->vdso_addr, __ATOMIC_ACQUIRE) + vdso_image.entry;
    uintptr_t new_rsp = frame_start - sizeof(return_address);
    error = user_memcpy((void *)new_rsp, &return_address, sizeof(return_address));
    if (unlikely(error)) return error;

    memset(current_thread->user_ctx, 0, sizeof(*current_thread->user_ctx));
    current_thread->user_ctx->cs = X86_64_USER_CS;
    current_thread->user_ctx->ss = X86_64_USER_DS;
    current_thread->user_ctx->rbx = frame_start;
    current_thread->user_ctx->rdi = info->__signo;
    current_thread->user_ctx->rsi = frame_start + offsetof(signal_frame_t, info);
    current_thread->user_ctx->rdx = frame_start + offsetof(signal_frame_t, context);
    current_thread->user_ctx->rsp = new_rsp;
    current_thread->user_ctx->rip = (uintptr_t)handler->__func.__handler;
    current_thread->user_ctx->rflags = 0x200;
    x86_64_xsave_reset(current_thread->arch.xsave);

    return 0;
}

int x86_64_sigreturn(uintptr_t ctx) {
    int error = verify_user_buffer(ctx, sizeof(signal_frame_t));
    if (unlikely(error)) return error;

    signal_frame_t frame;
    error = user_memcpy(&frame, (const void *)ctx, sizeof(frame));
    if (unlikely(error)) return error;

    __mcontext_t *mctx = &frame.context.__mcontext;

    if (unlikely(mctx->__rip > arch_pt_max_user_addr())) return EINVAL;

    error = verify_user_buffer((uintptr_t)mctx->__xsave_area, x86_64_xsave_size);
    if (unlikely(error)) return error;

    error = user_memcpy(current_thread->arch.xsave, mctx->__xsave_area, x86_64_xsave_size);
    if (unlikely(error)) {
        x86_64_xsave_reinit(current_thread->arch.xsave);
        return error;
    }

    x86_64_xsave_sanitize(current_thread->arch.xsave);
    x86_64_xsave_restore(current_thread->arch.xsave);

    arch_context_t *regs = current_thread->user_ctx;
    memset(regs, 0, sizeof(*regs));

    regs->cs = X86_64_USER_CS;
    regs->ss = X86_64_USER_DS;
    regs->rax = mctx->__rax;
    regs->rbx = mctx->__rbx;
    regs->rcx = mctx->__rcx;
    regs->rdx = mctx->__rdx;
    regs->rsi = mctx->__rsi;
    regs->rdi = mctx->__rdi;
    regs->rbp = mctx->__rbp;
    regs->rsp = mctx->__rsp;
    regs->r8 = mctx->__r8;
    regs->r9 = mctx->__r9;
    regs->r10 = mctx->__r10;
    regs->r11 = mctx->__r11;
    regs->r12 = mctx->__r12;
    regs->r13 = mctx->__r13;
    regs->r14 = mctx->__r14;
    regs->r15 = mctx->__r15;
    regs->rip = mctx->__rip;
    regs->rflags = (mctx->__rflags & 0x10dd5) | 0x200; // get RF, OF, DF, TF, SF, ZF, AF, PF, and CF from user

    arch_enter_user_mode_context(regs);
}
