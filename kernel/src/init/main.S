#include "mem/layout.h"

.text

#ifndef NDEBUG
.cfi_sections .debug_frame
#endif

.balign 16
.globl _entry
.type _entry, @function
_entry:
    .cfi_startproc
    .cfi_undefined rip
    .cfi_undefined rsp

    popfq # Limine puts a 0 on the stack, use it to reset rflags
    lea .Lstack_top(%rip), %rsp
    call kernel_main
    ud2

    .cfi_endproc
.size _entry, . - _entry

.bss

.balign 16
.type bsp_idle_stack, @object
bsp_idle_stack: .space KERNEL_STACK_SIZE
.Lstack_top:
.size bsp_idle_stack, . - bsp_idle_stack
