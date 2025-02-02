.text

#ifndef NDEBUG
.cfi_sections .debug_frame
#endif

.balign 16
.globl switch_thread
.type switch_thread, @function
switch_thread:
    .cfi_startproc
    mov %rdi, %rax

    sub $0x30, %rsp
    .cfi_adjust_cfa_offset 0x30

    mov %rbx, 0x00(%rsp)
    mov %rbp, 0x08(%rsp)
    mov %r12, 0x10(%rsp)
    mov %r13, 0x18(%rsp)
    mov %r14, 0x20(%rsp)
    mov %r15, 0x28(%rsp)
    .cfi_rel_offset %rbx, 0x00
    .cfi_rel_offset %rbp, 0x08
    .cfi_rel_offset %r12, 0x10
    .cfi_rel_offset %r13, 0x18
    .cfi_rel_offset %r14, 0x20
    .cfi_rel_offset %r15, 0x28

    mov %rsp, (%rdi)
    mov %rsi, %rsp

    mov 0x00(%rsp), %rbx
    mov 0x08(%rsp), %rbp
    mov 0x10(%rsp), %r12
    mov 0x18(%rsp), %r13
    mov 0x20(%rsp), %r14
    mov 0x28(%rsp), %r15
    .cfi_restore %rbx
    .cfi_restore %rbp
    .cfi_restore %r12
    .cfi_restore %r13
    .cfi_restore %r14
    .cfi_restore %r15

    add $0x30, %rsp
    .cfi_adjust_cfa_offset -0x30

    ret
    .cfi_endproc
.size switch_thread, . - switch_thread

.balign 16
.globl new_thread_thunk
.type new_thread_thunk, @function
new_thread_thunk:
    .cfi_startproc
    .cfi_undefined rip
    .cfi_undefined rsp

    mov %rax, %rdi
    mov %rbx, %rsi
    mov %r12, %rdx
    call sched_init_thread
    ud2

    .cfi_endproc
.size new_thread_thunk, . - new_thread_thunk
