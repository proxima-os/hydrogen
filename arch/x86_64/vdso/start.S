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
    mov %rbx, %rdi
    call x86_64_sigreturn
    ud2
    .cfi_endproc
.size _start, . - _start
