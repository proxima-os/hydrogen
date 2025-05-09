.section ".text._start", "ax", @progbits

.balign 16
.globl _start
.hidden _start
.type _start, @function
_start:
    call vdso_start
    ud2
.size _start, . - _start
