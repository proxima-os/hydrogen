.section ".text.memcmp", "ax", @progbits

.cfi_sections .debug_frame

.balign 16
.globl memcmp
.hidden memcmp
.type memcmp, @function
memcmp:
    .cfi_startproc
    xor %eax, %eax
    test %rdx, %rdx
    jz .Lcmp_done
    xor %ecx, %ecx
.balign 16
1:  mov (%rdi,%rcx,1), %al
    sub (%rsi,%rcx,1), %al
    jnz .Lcmp_done
    add $1, %rcx
    cmp %rcx, %rdx
    jne 1b
.balign 16
.Lcmp_done:
    movsx %al, %eax
    ret
    .cfi_endproc
.size memcmp, . - memcmp

.section ".text.memcpy", "ax", @progbits

.balign 16
.globl memcpy
.hidden memcpy
.type memcpy, @function
memcpy:
    .cfi_startproc
    mov %rdi, %rax
    mov %rdx, %rcx
    rep movsb
    ret
    .cfi_endproc
.size memcpy, . - memcpy

.section ".text.memmove", "ax", @progbits

.balign 16
.globl memmove
.hidden memmove
.type memmove, @function
memmove:
    .cfi_startproc
    mov %rdi, %rax
    mov %rdx, %rcx
    cmp %rsi, %rdi
    jb 1f
    je .Lmove_done
    sub $1, %rdx
    add %rdx, %rdi
    add %rdx, %rsi
    std
1:  rep movsb
    cld
.Lmove_done:
    ret
    .cfi_endproc
.size memmove, . - memmove

.section ".text.memset", "ax", @progbits

.globl memset
.hidden memset
.type memset, @function
memset:
    .cfi_startproc
    mov %rdi, %r8
    mov %esi, %eax
    mov %rdx, %rcx
    rep stosb
    mov %r8, %rax
    ret
    .cfi_endproc
.size memset, . - memset

.section ".note.GNU-stack", "", @progbits
