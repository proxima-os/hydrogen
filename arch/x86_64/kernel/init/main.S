#include "arch/stack.h"

.section ".init.text", "ax", @progbits

.cfi_sections .debug_frame

.balign 16
.globl _entry
.type _entry, @function
_entry:
    .cfi_startproc
    .cfi_undefined rip
    .cfi_undefined rsp
    popfq # bootloader pushes 0 to stack, use it to reset flags
    lea .Lstack_top(%rip), %rsp
    call x86_64_prepare_main
    call kernel_main
    ud2
    .cfi_endproc
.size _entry, . - _entry

.section ".bss.bsp_idle_stack", "aw", @nobits

.balign KERNEL_STACK_ALIGN
.type bsp_idle_stack, @object
bsp_idle_stack: .space KERNEL_STACK_SIZE
.Lstack_top:
.size bsp_idle_stack, . - bsp_idle_stack

.section ".note.GNU-stack", "", @progbits
