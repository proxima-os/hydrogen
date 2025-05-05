#include "x86_64/idt.h"
#include "cpu/smp.h"
#include "kernel/compiler.h"
#include "util/panic.h"
#include "x86_64/cpu.h"
#include "x86_64/cr.h"
#include "x86_64/idtvec.h"
#include "x86_64/lapic.h"
#include "x86_64/msr.h"
#include "x86_64/time.h"
#include "x86_64/tss.h"
#include <stdint.h>

static struct {
    uint64_t low;
    uint64_t high;
} idt[256];

extern uintptr_t x86_64_idt_thunks[256];

static void set_ist_idx(int vector, int index) {
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

_Noreturn void x86_64_idt_handle_fatal(x86_64_idt_frame_t *frame) {
    panic("fatal interrupt %U at 0x%X\n"
          "rax=%16X rbx=%16X rcx=%16X rdx=%16X\n"
          "rsi=%16X rdi=%16X rbp=%16X rsp=%16X\n"
          "r8 =%16X r9 =%16X r10=%16X r11=%16X\n"
          "r12=%16X r13=%16X r14=%16X r15=%16X\n"
          "rfl=%16X cr2=%16X cr3=%16X err=%16X\n"
          "cr0=0x%X cr4=0x%X cr8=0x%X cs=0x%X ss=0x%X",
          frame->vector,
          frame->rip,
          frame->rax,
          frame->rbx,
          frame->rcx,
          frame->rdx,
          frame->rsi,
          frame->rdi,
          frame->rbp,
          frame->rsp,
          frame->r8,
          frame->r9,
          frame->r10,
          frame->r11,
          frame->r12,
          frame->r13,
          frame->r14,
          frame->r15,
          frame->rflags,
          x86_64_read_cr2(),
          x86_64_read_cr3(),
          frame->error,
          x86_64_read_cr0(),
          x86_64_read_cr4(),
          x86_64_read_cr8(),
          frame->cs,
          frame->ss);
}

USED void x86_64_idt_dispatch(x86_64_idt_frame_t *frame) {
    switch (frame->vector) {
    case X86_64_IDT_NMI:
    case X86_64_IDT_DF:
    case X86_64_IDT_MC:
        if (x86_64_rdmsr(X86_64_MSR_GS_BASE) != *(uintptr_t *)&frame[1]) asm("swapgs");
        return x86_64_idt_handle_fatal(frame);
    case X86_64_IDT_IPI_REMOTE_CALL:
        smp_handle_remote_call();
        x86_64_lapic_eoi();
        return;
    case X86_64_IDT_LAPIC_TIMER: return x86_64_handle_timer();
    case X86_64_IDT_LAPIC_ERROR: return x86_64_lapic_irq_error();
    case X86_64_IDT_LAPIC_SPURIOUS: return x86_64_lapic_irq_spurious();
    default: return x86_64_idt_handle_fatal(frame);
    }
}
