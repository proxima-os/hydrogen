.text

# This is how Clang 19.1.0 compiles `int __popcountdi2(long value) { return __builtin_popcountl(value); }`
.balign 16
.globl __popcountdi2
.hidden __popcountdi2
.type __popcountdi2, @function
__popcountdi2:
    mov %rdi, %rax
    shr %rax
    movabs $0x5555555555555555, %rcx
    and %rax, %rcx
    sub %rcx, %rdi
    movabs $0x3333333333333333, %rax
    mov %rdi, %rcx
    and %rax, %rcx
    shr $2, %rdi
    and %rdi, %rax
    add %rcx, %rax
    mov %rax, %rcx
    shr $4, %rcx
    add %rax, %rcx
    movabs $0x0f0f0f0f0f0f0f0f, %rdx
    and %rcx, %rdx
    movabs $0x0101010101010101, %rax
    imul %rdx, %rax
    shr $56, %rax
    ret
.size __popcountdi2, . - __popcountdi2
