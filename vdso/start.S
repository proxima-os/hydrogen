.text

.balign 16
.globl _start
.type _start, @function
_start:
    mov %rsp, %rdi
    call vdso_start
    ud2
.size _start, . - _start
