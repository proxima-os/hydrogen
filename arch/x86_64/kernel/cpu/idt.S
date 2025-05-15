#include "x86_64/idtvec.h"

.section ".text.x86_64_idt_entry", "ax", @progbits

.cfi_sections .debug_frame

.balign 16
.type x86_64_idt_entry, @function
x86_64_idt_entry:
    .cfi_startproc
    .cfi_signal_frame
    .cfi_def_cfa rsp, 0x38
    .cfi_rel_offset rip, 0x10
    .cfi_rel_offset cs, 0x18
    .cfi_rel_offset rflags, 0x20
    .cfi_rel_offset rsp, 0x28
    .cfi_rel_offset ss, 0x30
    testl $3, 0x18(%rsp)
    jz 1f
    swapgs
1:

    sub $0x78, %rsp
    .cfi_adjust_cfa_offset 0x78
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

    .cfi_rel_offset rax, 0x00
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

    cld
    xor %ebp, %ebp
    mov %rsp, %rdi
    call x86_64_idt_dispatch

.Lidt_return:
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
    add $0x88, %rsp

    .cfi_adjust_cfa_offset -0x88
    .cfi_restore rax
    .cfi_restore rcx
    .cfi_restore rdx
    .cfi_restore rsi
    .cfi_restore rdi
    .cfi_restore rbp
    .cfi_restore r8
    .cfi_restore r9
    .cfi_restore r10
    .cfi_restore r11
    .cfi_restore r12
    .cfi_restore r13
    .cfi_restore r14
    .cfi_restore r15

    testl $3, 8(%rsp)
    jz 1f
    swapgs
1:  iretq
    .cfi_endproc
.size x86_64_idt_entry, . - x86_64_idt_entry

.section ".text.x86_64_jump_to_context", "ax", @progbits

.balign 16
.globl x86_64_jump_to_context
.type x86_64_jump_to_context, @function
x86_64_jump_to_context:
    .cfi_startproc
    mov %rdi, %rsp
    .cfi_undefined rip
    .cfi_undefined rsp
    jmp .Lidt_return
    .cfi_endproc
.size x86_64_jump_to_context, . - x86_64_jump_to_context

.section ".init.data", "aw", @progbits

.balign 8
.globl x86_64_idt_thunks
.type x86_64_idt_thunks, @object
x86_64_idt_thunks:

.section ".text.x86_64_idt_thunk_code", "ax", @progbits

.macro idt_thunk vector, errc=0
1:  .cfi_startproc
.if \errc == 0
    .cfi_def_cfa rsp, 0x28
    .cfi_rel_offset rip, 0x00
    .cfi_rel_offset cs, 0x08
    .cfi_rel_offset rflags, 0x10
    .cfi_rel_offset rsp, 0x18
    .cfi_rel_offset ss, 0x20
    pushq $0
    .cfi_adjust_cfa_offset 8
.else
    .cfi_def_cfa rsp, 0x30
    .cfi_rel_offset rip, 0x08
    .cfi_rel_offset cs, 0x10
    .cfi_rel_offset rflags, 0x18
    .cfi_rel_offset rsp, 0x20
    .cfi_rel_offset ss, 0x28
.endif
    pushq $\vector
    .cfi_adjust_cfa_offset 8
    jmp x86_64_idt_entry
    .cfi_endproc

.pushsection ".init.data", "aw", @progbits
.org \vector * 8
    .quad 1b
.popsection
.endm

idt_thunk X86_64_IDT_DE
idt_thunk X86_64_IDT_DB
idt_thunk X86_64_IDT_NMI
idt_thunk X86_64_IDT_BP
idt_thunk X86_64_IDT_OF
idt_thunk X86_64_IDT_BR
idt_thunk X86_64_IDT_UD
idt_thunk X86_64_IDT_NM
idt_thunk X86_64_IDT_DF, errc=1
idt_thunk X86_64_IDT_CS
idt_thunk X86_64_IDT_TS, errc=1
idt_thunk X86_64_IDT_NP, errc=1
idt_thunk X86_64_IDT_SS, errc=1
idt_thunk X86_64_IDT_GP, errc=1
idt_thunk X86_64_IDT_PF, errc=1
idt_thunk X86_64_IDT_MF
idt_thunk X86_64_IDT_AC
idt_thunk X86_64_IDT_MC
idt_thunk X86_64_IDT_XM

.set .Li, 32
.rept 0x100 - 32
idt_thunk .Li
.set .Li, .Li + 1
.endr

.section ".init.data", "aw", @progbits
.org 256 * 8
.size x86_64_idt_thunks, . - x86_64_idt_thunks
