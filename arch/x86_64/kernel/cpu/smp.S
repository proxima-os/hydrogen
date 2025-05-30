#include "smp.h"
#include "x86_64/msr.h"

.cfi_sections .debug_frame

.section ".init.text", "ax", @progbits

#define REL(x) ((x) - x86_64_smp_trampoline)

.balign 4096
.globl x86_64_smp_trampoline
.type x86_64_smp_trampoline, @object
x86_64_smp_trampoline:
.code16
    jmp .Lrm_entry
.code64
    .org 8

.Lcr4: .long 0
.Lcr3: .long 0
.Lcpu: .quad 0
.Lctx: .quad 0
.Lhhdm: .quad 0
.Lrsp: .quad 0
.Lefer: .quad 0
.Lfinal_cr3: .quad 0
.Lcr0: .long 0
.Ljmp_target:
    .long REL(.Lenter_64_bit_mode)
    .long .Lcs64
.Ljmp_target_wakeup:
    .long REL(.Lsetup_temp_cr3)
    .long .Lcs32
.Lflags: .word 0
.Lmtrr_count: .word 0
.Lmtrr_default: .quad 0
.Lmtrr_fixed:
.rept SMP_MTRR_NUM_FIXED
    .quad 0
.endr
.Lmtrr_variable:
.rept SMP_MTRR_VAR_MAX
    .quad 0
    .quad 0
.endr
.Lpat: .quad 0
.Lmtrr_fixed_msrs:
    .long X86_64_MSR_MTRR_FIX_64K_00000
    .long X86_64_MSR_MTRR_FIX_16K_80000
    .long X86_64_MSR_MTRR_FIX_16K_A0000
    .long X86_64_MSR_MTRR_FIX_4K_C0000
    .long X86_64_MSR_MTRR_FIX_4K_C8000
    .long X86_64_MSR_MTRR_FIX_4K_D0000
    .long X86_64_MSR_MTRR_FIX_4K_D8000
    .long X86_64_MSR_MTRR_FIX_4K_E0000
    .long X86_64_MSR_MTRR_FIX_4K_E8000
    .long X86_64_MSR_MTRR_FIX_4K_F0000
    .long X86_64_MSR_MTRR_FIX_4K_F8000
.Ltemp_gdt_desc:
    .word .Ltemp_gdt_end - .Ltemp_gdt
    .quad REL(.Ltemp_gdt)
.Ltemp_gdt:
    .quad 0
.set .Lcs32, . - .Ltemp_gdt
    .quad 0xcf9b000000ffff
.set .Lds32, . - .Ltemp_gdt
    .quad 0xcf93000000ffff
.set .Lcs64, . - .Ltemp_gdt
    .quad 0x209b0000000000
.set .Lds64, . - .Ltemp_gdt
    .quad 0x40930000000000
.Ltemp_gdt_end:

.code16
.Lrm_entry:
    lgdtl %cs:REL(.Ltemp_gdt_desc)

    mov %cs:REL(.Lcr4), %eax
    mov %eax, %cr4

    mov %cs:REL(.Lcr3), %eax
    mov %eax, %cr3

    mov %cs:REL(.Lefer), %eax
    mov %cs:REL(.Lefer + 4), %edx
    mov $X86_64_MSR_EFER, %ecx
    wrmsr

    mov %cs:REL(.Lcr0), %eax
    mov %eax, %cr0
    ljmpl *%cs:REL(.Ljmp_target)
.globl x86_64_smp_trampoline_wakeup_entry
x86_64_smp_trampoline_wakeup_entry:
.code64
    # firmware puts us here with the page we're in identity mapped and interrupts disabled,
    # but we don't get to specify which paging mode we want to be in. drop down to 32-bit
    # mode and set our control regs from there.
    lgdtq .Ltemp_gdt_desc(%rip)
    lea x86_64_smp_trampoline(%rip), %rbp
    ljmpl *.Ljmp_target_wakeup(%rip)
.Lsetup_temp_cr3:
.code32
    mov $.Lds32, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %fs
    mov %eax, %gs
    mov %eax, %ss
    # now in compatibility mode

    # disable paging to exit long mode
    mov %cr0, %eax
    and $~(1 << 31), %eax
    mov %eax, %cr0

    # enter long mode again, this time with our preferred paging mode
    mov REL(.Lcr4)(%ebp), %eax
    mov %eax, %cr4

    mov REL(.Lcr3)(%ebp), %eax
    mov %eax, %cr3

    mov REL(.Lefer)(%ebp), %eax
    mov REL(.Lefer + 4)(%ebp), %edx
    mov $X86_64_MSR_EFER, %ecx
    wrmsr

    mov REL(.Lcr0)(%ebp), %eax
    mov %eax, %cr0
    ljmpl *REL(.Ljmp_target)(%ebp)
.code64
.Lenter_64_bit_mode:
    mov $.Lds64, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %fs
    mov %eax, %gs
    mov %eax, %ss

    # disable caching
    mov %cr0, %rax
    or $(1 << 30), %eax
    mov %rax, %cr0
    wbinvd

    # flush tlb
    mov %cr4, %rax
    and $~((1 << 17) | (1 << 7)), %eax
    mov %rax, %cr4
    mov %cr3, %rax
    mov %rax, %cr3

    # disable mtrr
    mov $X86_64_MSR_MTRR_DEF_TYPE, %ecx
    rdmsr
    and $~(1 << 11), %eax
    wrmsr

    # synchronize mtrrs
    testw $SMP_MTRR_SAVED, .Lflags(%rip)
    jz .Lmtrr_done

    movzwl .Lmtrr_count(%rip), %ebx
    test %ebx, %ebx
    jz .Lmtrr_var_done

    lea .Lmtrr_variable(%rip), %rsi
    mov $0x200, %ecx

1:  mov (%rsi), %eax
    mov 4(%rsi), %edx
    wrmsr
    inc %ecx
    mov 8(%rsi), %eax
    mov 12(%rsi), %edx
    wrmsr
    inc %ecx
    add $16, %rsi
    dec %ebx
    jnz 1b

.Lmtrr_var_done:

    testw $SMP_MTRR_FIXED, .Lflags(%rip)
    jz .Lmtrr_fixed_done

    lea .Lmtrr_fixed(%rip), %rsi
    lea .Lmtrr_fixed_msrs(%rip), %rdi
    mov $SMP_MTRR_NUM_FIXED, %ebx
1:  mov (%rsi), %eax
    mov 4(%rsi), %edx
    mov (%rdi), %ecx
    wrmsr
    add $8, %esi
    add $4, %edi
    dec %ebx
    jnz 1b

.Lmtrr_fixed_done:
    mov .Lmtrr_default(%rip), %eax
    mov (.Lmtrr_default + 4)(%rip), %edx
    mov $X86_64_MSR_MTRR_DEF_TYPE, %ecx
    wrmsr
.Lmtrr_done:

    # synchronize pat
    testw $SMP_PAT_SAVED, .Lflags(%rip)
    jz .Lpat_done
    mov .Lpat(%rip), %eax
    mov (.Lpat + 4)(%rip), %edx
    mov $X86_64_MSR_PAT, %ecx
    wrmsr
.Lpat_done:

    # flush tlb again
    mov %cr3, %rax
    mov %rax, %cr3

    # reenable caching
    wbinvd
    mov %cr0, %rax
    and $~(1 << 30), %eax
    mov %rax, %cr0

    # restore cr4
    mov .Lcr4(%rip), %eax
    mov %rax, %cr4

    # use proper addresses and page tables
    mov .Lcpu(%rip), %rdi
    mov .Lctx(%rip), %rsi
    lea .Lrsp(%rip), %rdx
    add .Lhhdm(%rip), %rdx
    mov .Lfinal_cr3(%rip), %rcx
    movabs $1f, %rax
    jmp *%rax
1:  mov %rcx, %cr3

    # take our idle stack (this also tells the smp code that we're responsive, has to be atomic)
    xor %esp, %esp
    xchg %rsp, (%rdx)

    # set up call convention
    xor %ebp, %ebp
    pushq $0
    popfq

    .cfi_startproc
    .cfi_undefined rip
    .cfi_undefined rsp
    call x86_64_smp_init_current
    ud2
    .cfi_endproc

.globl x86_64_smp_trampoline_end
x86_64_smp_trampoline_end:
.size x86_64_smp_trampoline, . - x86_64_smp_trampoline

.section ".note.GNU-stack", "", @progbits
