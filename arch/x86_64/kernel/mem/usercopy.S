.text

.cfi_sections .debug_frame

.globl x86_64_usercopy_start, x86_64_usercopy_end

x86_64_usercopy_start:

.balign 16
.globl user_memcpy
.type user_memcpy, @function
user_memcpy:
    .cfi_startproc
    mov %rdx, %rcx
    xor %edx, %edx
    rep movsb
    mov %edx, %eax
    ret
    .cfi_endproc
.size user_memcpy, . - user_memcpy

.balign 16
.globl user_memset
.type user_memset, @function
user_memset:
    .cfi_startproc
    mov %esi, %eax
    mov %rdx, %rcx
    xor %edx, %edx
    rep stosb
    mov %edx, %eax
    ret
    .cfi_endproc
.size user_memset, . - user_memset

x86_64_usercopy_end:
