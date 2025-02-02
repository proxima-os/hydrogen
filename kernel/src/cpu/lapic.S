.text

#ifndef NDEBUG
.cfi_sections .debug_frame
#endif

.balign 16
.globl smp_cpu_thunk
.type smp_cpu_thunk, @function
smp_cpu_thunk:
    .cfi_startproc
    .cfi_undefined rip
    .cfi_undefined rsp

    mov 24(%rdi), %rbx
    call pmap_init_switch # allocated stack might not be in hhdm
    mov %rbx, %rdi
    mov (%rdi), %rsp
    call smp_init_cpu
    ud2

    .cfi_endproc
.size smp_cpu_thunk, . - smp_cpu_thunk
