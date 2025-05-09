.text

.cfi_sections .debug_frame

.globl x86_64_usercopy_start, x86_64_usercopy_end

x86_64_usercopy_start:

.balign 16
.globl x86_64_user_memcpy_regular
.type x86_64_user_memcpy_regular, @function
x86_64_user_memcpy_regular:
    .cfi_startproc
    mov %rdx, %rcx
    xor %edx, %edx
    rep movsb
    mov %edx, %eax
    ret
    .cfi_endproc
.size x86_64_user_memcpy_regular, . - x86_64_user_memcpy_regular

.balign 16
.globl x86_64_user_memset_regular
.type x86_64_user_memset_regular, @function
x86_64_user_memset_regular:
    .cfi_startproc
    mov %esi, %eax
    mov %rdx, %rcx
    xor %edx, %edx
    rep stosb
    mov %edx, %eax
    ret
    .cfi_endproc
.size x86_64_user_memset_regular, . - x86_64_user_memset_regular

.balign 16
.globl x86_64_user_memcpy_smap
.type x86_64_user_memcpy_smap, @function
x86_64_user_memcpy_smap:
    .cfi_startproc
    mov %rdx, %rcx
    xor %edx, %edx
    stac
    rep movsb
    clac
    mov %edx, %eax
    ret
    .cfi_endproc
.size x86_64_user_memcpy_smap, . - x86_64_user_memcpy_smap

.balign 16
.globl x86_64_user_memset_smap
.type x86_64_user_memset_smap, @function
x86_64_user_memset_smap:
    .cfi_startproc
    mov %esi, %eax
    mov %rdx, %rcx
    xor %edx, %edx
    stac
    rep stosb
    clac
    mov %edx, %eax
    ret
    .cfi_endproc
.size x86_64_user_memset_smap, . - x86_64_user_memset_smap

x86_64_usercopy_end:
