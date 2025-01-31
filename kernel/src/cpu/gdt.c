#include "cpu/gdt.h"
#include "asm/msr.h"
#include "asm/tables.h"
#include "cpu/cpu.h"

extern void reload_segments(size_t code_sel);

void init_gdt(struct cpu *cpu) {
    uintptr_t tss_addr = (uintptr_t)&cpu->tss;

    cpu->gdt.kern_code = 0x209b0000000000;
    cpu->gdt.kern_data = 0x40930000000000;
    cpu->gdt.user_data = 0x40f30000000000 | cpu->id; // store cpu id in user data limit
    cpu->gdt.user_code = 0x20fb0000000000;
    cpu->gdt.tss_low = (sizeof(cpu->tss) - 1) | ((tss_addr & 0xffffff) << 16) | (0x89ul << 40) |
                       ((tss_addr & 0xff000000) << 32);
    cpu->gdt.tss_high = tss_addr >> 32;

    load_gdt(&cpu->gdt, sizeof(cpu->gdt));
    load_ldt(0);
    load_tss(SEL_TSS);
    reload_segments(SEL_KCODE);
    wrmsr(MSR_GS_BASE, (uintptr_t)cpu);
}
