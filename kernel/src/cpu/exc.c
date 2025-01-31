#include "cpu/exc.h"
#include "asm/cr.h"
#include "compiler.h"
#include "cpu/idt.h"
#include "cpu/irqvecs.h"
#include "util/panic.h"

_Noreturn void handle_fatal_exception(idt_frame_t *frame, UNUSED void *ctx) {
    panic("fatal interrupt %U at 0x%X\n"
          "rax=0x%16X rbx=0x%16X rcx=0x%16X rdx=0x%16X\n"
          "rsi=0x%16X rdi=0x%16X rbp=0x%16X rsp=0x%16X\n"
          "r8 =0x%16X r9 =0x%16X r10=0x%16X r11=0x%16X\n"
          "r12=0x%16X r13=0x%16X r14=0x%16X r15=0x%16X\n"
          "rfl=0x%16X cr2=0x%16X cr3=0x%16X err=0x%16X\n"
          "cr0=0x%X cr4=0x%X cr8=0x%X cs=%4X ss=%4X",
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
          read_cr2(),
          read_cr3(),
          frame->error_code,
          read_cr0(),
          read_cr4(),
          read_cr8(),
          frame->cs,
          frame->ss);
}

static _Noreturn void handle_fatal_exception_paranoid(idt_frame_t *frame, void *ctx) {
    idt_paranoid_entry(frame);
    handle_fatal_exception(frame, ctx);
}

void init_exceptions(void) {
    idt_install(VEC_DIVIDE_ERROR, handle_fatal_exception, NULL);
    idt_install(VEC_DEBUG, handle_fatal_exception, NULL);
    idt_install(VEC_NMI, handle_fatal_exception_paranoid, NULL);
    idt_install(VEC_BREAKPOINT, handle_fatal_exception, NULL);
    idt_install(VEC_OVERFLOW, handle_fatal_exception, NULL);
    idt_install(VEC_UNDEFINED_OPCODE, handle_fatal_exception, NULL);
    idt_install(VEC_DEVICE_UNAVAILABLE, handle_fatal_exception, NULL);
    idt_install(VEC_DOUBLE_FAULT, handle_fatal_exception_paranoid, NULL);
    idt_install(VEC_INVALID_TSS, handle_fatal_exception, NULL);
    idt_install(VEC_INVALID_SEGMENT, handle_fatal_exception, NULL);
    idt_install(VEC_STACK_FAULT, handle_fatal_exception, NULL);
    idt_install(VEC_GENERAL_FAULT, handle_fatal_exception, NULL);
    idt_install(VEC_PAGE_FAULT, handle_fatal_exception, NULL);
    idt_install(VEC_FPU_ERROR, handle_fatal_exception, NULL);
    idt_install(VEC_ALIGNMENT_ERROR, handle_fatal_exception, NULL);
    idt_install(VEC_MACHINE_CHECK, handle_fatal_exception_paranoid, NULL);
    idt_install(VEC_SIMD_ERROR, handle_fatal_exception, NULL);
    idt_install(VEC_VIRTUALIZATION_ERROR, handle_fatal_exception, NULL);
    idt_install(VEC_CONTROL_PROTECTION_ERROR, handle_fatal_exception, NULL);
    idt_install(VEC_IRQ_APIC_ERR, handle_fatal_exception, NULL);
}
