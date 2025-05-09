.section ".text.x86_64_enter_user_mode", "ax", @progbits

.cfi_sections .debug_frame

.balign 16
.globl x86_64_enter_user_mode
.type x86_64_enter_user_mode, @function
x86_64_enter_user_mode:
    .cfi_startproc

    # prepare stack frame for iretq
    sub $40, %rsp
    .cfi_adjust_cfa_offset 40
    mov %rdi, 0x00(%rsp) # rip
    mov %rsi, 0x08(%rsp) # cs
    mov %rdx, 0x10(%rsp) # rflags
    mov %rcx, 0x18(%rsp) # rsp
    mov %r8, 0x20(%rsp)  # ss

    # clear registers and return
    xor %eax, %eax
    xor %ebx, %ebx
    xor %ecx, %ecx
    xor %edx, %edx
    xor %esi, %esi
    xor %edi, %edi
    xor %ebp, %ebp
    xor %r8d, %r8d
    xor %r9d, %r9d
    xor %r10d, %r10d
    xor %r11d, %r11d
    xor %r12d, %r12d
    xor %r13d, %r13d
    xor %r14d, %r14d
    xor %r15d, %r15d
    swapgs
    iretq
    .cfi_endproc
.size x86_64_enter_user_mode, . - x86_64_enter_user_mode
