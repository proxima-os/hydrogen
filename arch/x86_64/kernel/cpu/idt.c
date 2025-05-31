#include "x86_64/idt.h"
#include "arch/context.h"
#include "arch/irq.h"
#include "cpu/cpudata.h"
#include "cpu/smp.h"
#include "kernel/compiler.h"
#include "mem/pmap.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "sys/transition.h"
#include "util/panic.h"
#include "util/printk.h"
#include "x86_64/cpu.h"
#include "x86_64/cr.h"
#include "x86_64/idtvec.h"
#include "x86_64/lapic.h"
#include "x86_64/msr.h"
#include "x86_64/time.h"
#include "x86_64/tss.h"
#include <hydrogen/signal.h>
#include <stdint.h>

static struct {
    uint64_t low;
    uint64_t high;
} idt[256];

extern uintptr_t x86_64_idt_thunks[256];

static void set_ist_idx(int vector, x86_64_ist_index_t index) {
    idt[vector].low |= ((uint64_t)(index + 1) << 32);
}

void x86_64_idt_init(void) {
    struct {
        uint16_t limit;
        void *base;
    } __attribute__((packed)) desc = {sizeof(idt) - 1, idt};
    asm("lidt %0" ::"m"(desc));

    for (int i = 0; i < 256; i++) {
        uintptr_t thunk = x86_64_idt_thunks[i];
        if (!thunk) continue;

        idt[i].low = (thunk & 0xffff) | (X86_64_KERN_CS << 16) | ((thunk & 0xffff0000) << 32) | (0x8eull << 40);
        idt[i].high = thunk >> 32;
    }

    set_ist_idx(X86_64_IDT_NMI, X86_64_IST_FATAL);
    set_ist_idx(X86_64_IDT_DF, X86_64_IST_FATAL);
    set_ist_idx(X86_64_IDT_MC, X86_64_IST_FATAL);
}

_Noreturn void x86_64_idt_handle_fatal(arch_context_t *context) {
    panic(
        "fatal interrupt %U at 0x%X\n"
        "rax=%16X rbx=%16X rcx=%16X rdx=%16X\n"
        "rsi=%16X rdi=%16X rbp=%16X rsp=%16X\n"
        "r8 =%16X r9 =%16X r10=%16X r11=%16X\n"
        "r12=%16X r13=%16X r14=%16X r15=%16X\n"
        "rfl=%16X cr2=%16X cr3=%16X err=%16X\n"
        "cr0=0x%X cr4=0x%X cr8=0x%X cs=0x%X ss=0x%X",
        context->vector,
        context->rip,
        context->rax,
        context->rbx,
        context->rcx,
        context->rdx,
        context->rsi,
        context->rdi,
        context->rbp,
        context->rsp,
        context->r8,
        context->r9,
        context->r10,
        context->r11,
        context->r12,
        context->r13,
        context->r14,
        context->r15,
        context->rflags,
        x86_64_read_cr2(),
        x86_64_read_cr3(),
        context->error,
        x86_64_read_cr0(),
        x86_64_read_cr4(),
        x86_64_read_cr8(),
        context->cs,
        context->ss
    );
}

static void signal_or_fatal(arch_context_t *context, int signal, int code) {
    if ((context->cs & 3) == 0) x86_64_idt_handle_fatal(context);

    __siginfo_t info = {.__signo = signal, .__code = code, .__data.__sigsegv.__address = (void *)context->rip};
    printk(
        "idt: sending signal %d to thread %d (process %d) due to exception %U at 0x%Z (code: %d)\n",
        signal,
        current_thread->pid->id,
        current_thread->process->pid->id,
        context->vector,
        context->rip,
        code
    );
    queue_signal(
        current_thread->process,
        &current_thread->sig_target,
        &info,
        QUEUE_SIGNAL_FORCE,
        &current_thread->fault_sig
    );
}

USED void x86_64_idt_dispatch(arch_context_t *context) {
    if (x86_64_cpu_features.smap) asm("clac");

    if (context->vector == X86_64_IDT_NMI || context->vector == X86_64_IDT_DF || context->vector == X86_64_IDT_MC) {
        x86_64_wrmsr(X86_64_MSR_GS_BASE, *(uintptr_t *)&context[1]);
        return x86_64_idt_handle_fatal(context);
    }

    if (context->cs & 3) enter_from_user_mode(context);

    switch (context->vector) {
    case X86_64_IDT_DE: signal_or_fatal(context, __SIGFPE, __FPE_INTDIV); break;
    case X86_64_IDT_DB: signal_or_fatal(context, __SIGTRAP, __TRAP_TRACE); break;
    case X86_64_IDT_BP: signal_or_fatal(context, __SIGTRAP, __TRAP_BRKPT); break;
    case X86_64_IDT_OF: signal_or_fatal(context, __SIGSEGV, 0); break;
    case X86_64_IDT_BR: signal_or_fatal(context, __SIGSEGV, 0); break;
    case X86_64_IDT_UD: signal_or_fatal(context, __SIGILL, __ILL_ILLOPN); break;
    case X86_64_IDT_NM: signal_or_fatal(context, __SIGFPE, 0); break;
    case X86_64_IDT_CS: signal_or_fatal(context, __SIGSEGV, 0); break;
    case X86_64_IDT_TS: signal_or_fatal(context, __SIGSEGV, 0); break;
    case X86_64_IDT_NP: signal_or_fatal(context, __SIGSEGV, 0); break;
    case X86_64_IDT_SS: signal_or_fatal(context, __SIGSEGV, 0); break;
    case X86_64_IDT_GP: signal_or_fatal(context, __SIGSEGV, 0); break;
    case X86_64_IDT_PF: {
        uintptr_t address = x86_64_read_cr2();
        enable_irq();

        pmap_fault_type_t type;
        unsigned flags = 0;

        if (context->error & (1u << 4)) type = PMAP_FAULT_EXECUTE;
        else if (context->error & (1u << 1)) type = PMAP_FAULT_WRITE;
        else type = PMAP_FAULT_READ;

        if (context->error & (1u << 2)) flags |= PMAP_FAULT_USER;

        pmap_handle_page_fault(context, context->rip, address, type, flags);
        break;
    }
    case X86_64_IDT_MF: signal_or_fatal(context, __SIGFPE, 0); break;
    case X86_64_IDT_AC: signal_or_fatal(context, __SIGBUS, __BUS_ADRALN); break;
    case X86_64_IDT_XM: signal_or_fatal(context, __SIGFPE, 0); break;
    case X86_64_IDT_IPI_REMOTE_CALL: {
        preempt_lock();
        smp_handle_remote_call();
        x86_64_lapic_eoi();
        preempt_unlock();
        break;
    }
    case X86_64_IDT_LAPIC_TIMER: x86_64_handle_timer(); break;
    case X86_64_IDT_LAPIC_ERROR: x86_64_lapic_irq_error(); break;
    case X86_64_IDT_LAPIC_SPURIOUS: x86_64_lapic_irq_spurious(); break;
    case X86_64_IDT_IRQ_MIN ... X86_64_IDT_IRQ_MAX: x86_64_lapic_irq_handle(context->vector); break;
    default: x86_64_idt_handle_fatal(context); break;
    }

    if (context->cs & 3) exit_to_user_mode(-1);
}
