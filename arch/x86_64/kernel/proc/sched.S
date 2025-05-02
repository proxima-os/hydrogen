.section ".text.x86_64_switch_thread", "ax", @progbits

#ifndef NDEBUG
.cfi_sections .debug_frame
#endif

.balign 16
.globl x86_64_switch_thread
.type x86_64_switch_thread, @function
x86_64_switch_thread:
    .cfi_startproc

    sub $0x30, %rsp
    .cfi_adjust_cfa_offset 0x30

    mov %rbx, 0x00(%rsp)
    mov %rbp, 0x08(%rsp)
    mov %r12, 0x10(%rsp)
    mov %r13, 0x18(%rsp)
    mov %r14, 0x20(%rsp)
    mov %r15, 0x28(%rsp)
    .cfi_rel_offset rbx, 0x00
    .cfi_rel_offset rbp, 0x08
    .cfi_rel_offset r12, 0x10
    .cfi_rel_offset r13, 0x18
    .cfi_rel_offset r14, 0x20
    .cfi_rel_offset r15, 0x28

    mov %rsp, (%rdi)
    mov %rsi, %rsp

    mov 0x00(%rsp), %rbx
    mov 0x08(%rsp), %rbp
    mov 0x10(%rsp), %r12
    mov 0x18(%rsp), %r13
    mov 0x20(%rsp), %r14
    mov 0x28(%rsp), %r15
    add $0x30, %rsp
    .cfi_adjust_cfa_offset -0x30
    .cfi_restore rbx
    .cfi_restore rbp
    .cfi_restore r12
    .cfi_restore r13
    .cfi_restore r14
    .cfi_restore r15
    mov %rdi, %rax
    ret
    .cfi_endproc
.size x86_64_switch_thread, . - x86_64_switch_thread

.section ".text.x86_64_thread_entry", "ax", @progbits

.balign 16
.globl x86_64_thread_entry
.type x86_64_thread_entry, @function
x86_64_thread_entry:
    .cfi_startproc
    .cfi_undefined rip
    .cfi_undefined rsp
    mov %rax, %rdi
    mov %rbx, %rsi
    mov %r12, %rdx
    call x86_64_init_thread
    ud2
    .cfi_endproc
.size x86_64_thread_entry, . - x86_64_thread_entry
