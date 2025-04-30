#include "cpu/irqvecs.h"

#ifndef NDEBUG
.cfi_sections .debug_frame
#endif

.section ".rodata.idt_stubs", "a", @progbits
.balign 8
.globl idt_stubs
.type idt_stubs, @object
idt_stubs:

.text

.balign 16
.type idt_stub_common, @function
idt_stub_common:
    testl $3, 24(%rsp)
    jz 1f
    swapgs
1:  sub $120, %rsp
    mov %rax, 0x00(%rsp)
    mov %rbx, 0x08(%rsp)
    mov %rcx, 0x10(%rsp)
    mov %rdx, 0x18(%rsp)
    mov %rsi, 0x20(%rsp)
    mov %rdi, 0x28(%rsp)
    mov %rbp, 0x30(%rsp)
    mov %r8, 0x38(%rsp)
    mov %r9, 0x40(%rsp)
    mov %r10, 0x48(%rsp)
    mov %r11, 0x50(%rsp)
    mov %r12, 0x58(%rsp)
    mov %r13, 0x60(%rsp)
    mov %r14, 0x68(%rsp)
    mov %r15, 0x70(%rsp)

    .cfi_startproc
    .cfi_def_cfa rsp, 176
    .cfi_rel_offset rax, 0x00
    .cfi_rel_offset rbx, 0x08
    .cfi_rel_offset rcx, 0x10
    .cfi_rel_offset rdx, 0x18
    .cfi_rel_offset rsi, 0x20
    .cfi_rel_offset rdi, 0x28
    .cfi_rel_offset rbp, 0x30
    .cfi_rel_offset r8, 0x38
    .cfi_rel_offset r9, 0x40
    .cfi_rel_offset r10, 0x48
    .cfi_rel_offset r11, 0x50
    .cfi_rel_offset r12, 0x58
    .cfi_rel_offset r13, 0x60
    .cfi_rel_offset r14, 0x68
    .cfi_rel_offset r15, 0x70
    .cfi_rel_offset rip, 0x88
    .cfi_rel_offset cs, 0x90
    .cfi_rel_offset rflags, 0x98
    .cfi_rel_offset rsp, 0xa0
    .cfi_rel_offset ss, 0xa8

    cld
#ifndef NDEBUG
    xor %ebp, %ebp
#endif
    mov %rsp, %rdi
    call idt_dispatch

    .cfi_endproc

.Ldo_irq_ret:
    cli
    mov 0x00(%rsp), %rax
    mov 0x08(%rsp), %rbx
    mov 0x10(%rsp), %rcx
    mov 0x18(%rsp), %rdx
    mov 0x20(%rsp), %rsi
    mov 0x28(%rsp), %rdi
    mov 0x30(%rsp), %rbp
    mov 0x38(%rsp), %r8
    mov 0x40(%rsp), %r9
    mov 0x48(%rsp), %r10
    mov 0x50(%rsp), %r11
    mov 0x58(%rsp), %r12
    mov 0x60(%rsp), %r13
    mov 0x68(%rsp), %r14
    mov 0x70(%rsp), %r15
    add $136, %rsp
    testl $3, 8(%rsp)
    jz 1f
    swapgs
1:  iretq
.size idt_stub_common, . - idt_stub_common

.balign 16
.globl return_from_fork
.type return_from_fork, @function
return_from_fork:
    mov %rdi, %rsp
    jmp .Ldo_irq_ret
.size return_from_fork, . - return_from_fork

.macro idt_stub vector, errc=0
1:
.if \errc == 0
    pushq $0
.endif
    pushq $\vector
    jmp idt_stub_common

.pushsection ".rodata.idt_stubs", "a", @progbits
    .org \vector * 8
    .quad 1b
.popsection
.endm

.balign 16
.type idt_stub_code, @function
idt_stub_code:

idt_stub 0x00
idt_stub 0x01
idt_stub 0x02
idt_stub 0x03
idt_stub 0x04
idt_stub 0x06
idt_stub 0x07
idt_stub 0x08, errc=1
idt_stub 0x0a, errc=1
idt_stub 0x0b, errc=1
idt_stub 0x0c, errc=1
idt_stub 0x0d, errc=1
idt_stub 0x0e, errc=1
idt_stub 0x10
idt_stub 0x11, errc=1
idt_stub 0x12
idt_stub 0x13
idt_stub 0x14
idt_stub 0x15, errc=1

.set .Li, 0x20
.rept 0x100 - .Li
    idt_stub .Li
    .set .Li, .Li + 1
.endr

.size idt_stub_code, . - idt_stub_code

.pushsection ".rodata.idt_stubs", "a", @progbits
    .org 0x100 * 8
.size idt_stubs, . - idt_stubs
.popsection
