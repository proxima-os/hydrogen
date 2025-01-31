.text

.balign 16
.globl reload_segments
.type reload_segments, @function
reload_segments:
    lea 1f(%rip), %rax
    push %rdi
    push %rax
    lretq
1:  xor %eax, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %fs
    mov %eax, %gs
    mov %eax, %ss
    ret
.size reload_segments, . - reload_segments
