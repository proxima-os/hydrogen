.text

.balign 16

# If a fatal page fault is taken while accessing user-space memory with rip between .Lusermem_start and .Lusermem_end,
# instead of triggering a kernel panic, rip is set to .Lusermem_ret and rax is set to an error code. Additionally, if
# SMAP is supported, rFLAGS.AC is set to 0.

.Lusermem_start:

.globl bare_memcpy_user
.type bare_memcpy_user, @function
bare_memcpy_user:
    mov %rdx, %rcx
    rep movsb
    xor %eax, %eax
.Lusermem_ret:
    ret
.size bare_memcpy_user, . - bare_memcpy_user

.globl bare_memset_user
.type bare_memset_user, @function
bare_memset_user:
    mov %rsi, %rax
    mov %rdx, %rcx
    rep stosb
    xor %eax, %eax
    ret
.size bare_memset_user, . - bare_memset_user

.globl smap_memcpy_user
.type smap_memcpy_user, @function
smap_memcpy_user:
    mov %rdx, %rcx
    stac
    rep movsb
    clac
    xor %eax, %eax
    ret
.size smap_memcpy_user, . - smap_memcpy_user

.globl smap_memset_user
.type smap_memset_user, @function
smap_memset_user:
    mov %rsi, %rax
    mov %rdx, %rcx
    stac
    rep stosb
    clac
    xor %eax, %eax
    ret
.size smap_memset_user, . - smap_memset_user

.Lusermem_end:

.section ".rodata.usermem_funcs", "a", @progbits

.balign 8
.globl usermem_funcs
.type usermem_funcs, @object
usermem_funcs:
    .quad .Lusermem_start
    .quad .Lusermem_end
    .quad .Lusermem_ret
.size usermem_funcs, . - usermem_funcs
