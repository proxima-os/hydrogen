.section ".text.x86_64_syscall_entry", "ax", @progbits

.cfi_sections .debug_frame

.balign 16
.globl x86_64_syscall_entry
.type x86_64_syscall_entry, @function
x86_64_syscall_entry:
    .cfi_startproc
    .cfi_signal_frame
    .cfi_def_cfa rsp, 0
    .cfi_same_value rsp
    .cfi_register rip, rcx
    .cfi_register rflags, r11
    swapgs
    mov %rsp, %gs:(0)  # save user stack
    mov %gs:(12), %rsp # load rsp0
    .cfi_undefined rsp
    sub $0xb0, %rsp
    .cfi_adjust_cfa_offset 0xb0
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
    mov %rcx, 0x88(%rsp)
    mov %r11, 0x98(%rsp)
    .cfi_rel_offset rax, 0x00

    mov %gs:(0), %rax
    mov %rax, 0xa0(%rsp)

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
    .cfi_rel_offset rflags, 0x98
    .cfi_rel_offset rsp, 0xa0

    xor %ebp, %ebp
    mov %rsp, %rdi
    call x86_64_syscall_dispatch

    cli
    mov 0x00(%rsp), %rax
    mov 0x08(%rsp), %rbx
    mov 0x18(%rsp), %rdx
    mov 0x20(%rsp), %rsi
    mov 0x28(%rsp), %rdi
    mov 0x30(%rsp), %rbp
    mov 0x38(%rsp), %r8
    mov 0x40(%rsp), %r9
    mov 0x48(%rsp), %r10
    mov 0x58(%rsp), %r12
    mov 0x60(%rsp), %r13
    mov 0x68(%rsp), %r14
    mov 0x70(%rsp), %r15
    mov 0x88(%rsp), %rcx
    mov 0x98(%rsp), %r11
    mov 0xa0(%rsp), %rsp

    .cfi_def_cfa rsp, 0
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
    .cfi_register rip, rcx
    .cfi_register rflags, r11
    .cfi_same_value rsp

    swapgs
    sysretq
    .cfi_endproc
.size x86_64_syscall_entry, . - x86_64_syscall_entry
