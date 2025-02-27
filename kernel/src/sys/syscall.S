.text

#ifndef NDEBUG
.cfi_sections .debug_frame
#endif

.balign 16
.globl syscall_entry
.type syscall_entry, @function
syscall_entry:
    swapgs
    mov %rsp, %gs:(0)  # save user stack
    mov %gs:(12), %rsp # load rsp0

    sub $0xb0, %rsp
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
    mov %gs:(0), %rax
    mov %rax, 0xa0(%rsp)

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

    mov %rsp, %rdi
    call syscall_dispatch

    .cfi_endproc

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
    swapgs
    sysretq
.size syscall_entry, . - syscall_entry

.balign 16
.globl do_enter_umode
.type do_enter_umode, @function
do_enter_umode:
    # prepare iretq frame
    push %r8
    push %rsi
    push %rdx
    push %rcx
    push %rdi

    # zero registers
    cli
    xor %eax, %eax
    xor %ebx, %ebx
    xor %ecx, %ecx
    xor %edx, %edx
    xor %edi, %edi
    xor %esi, %esi
    xor %ebp, %ebp
    xor %r8d, %r8d
    xor %r9d, %r9d
    xor %r10d, %r10d
    xor %r11d, %r11d
    xor %r12d, %r12d
    xor %r13d, %r13d
    xor %r14d, %r14d
    xor %r15d, %r15d
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %fs
    swapgs
    mov %eax, %gs
    iretq
.size do_enter_umode, . - do_enter_umode
