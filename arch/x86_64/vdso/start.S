.section ".text._start", "ax", @progbits

.cfi_sections .debug_frame

.balign 16
.globl _start
.hidden _start
.type _start, @function
_start:
    .cfi_startproc
    .cfi_signal_frame
    .cfi_undefined rip
    .cfi_undefined rsp
    test %rbx, %rbx
    jz 1f
    mov %rbx, %rdi
    call x86_64_sigreturn
    jmp 2f
1:  call vdso_start
2:  ud2
    .cfi_endproc
.size _start, . - _start
