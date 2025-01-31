#include "cpu/cpu.h"
#include "asm/cpuid.h"
#include "asm/cr.h"
#include "cpu/idt.h"
#include "mem/layout.h"

#define CR0_CLEAR_MASK (CR0_CD | CR0_NW | CR0_EM | CR0_TS)
#define CR0_SET_MASK (CR0_AM | CR0_NE | CR0_MP)

cpu_features_t cpu_features;

void detect_cpu_features(void) {
    uint32_t eax, ebx, ecx, edx;

    // get basic cpuid info that's guaranteed to be present
    uint32_t std_limit;
    uint32_t ext_limit;
    cpuid(0, &std_limit, &ebx, &ecx, &edx);
    cpuid(0x80000000, &ext_limit, &ebx, &ecx, &edx);
    cpuid(1, &eax, &ebx, &ecx, &edx);

    // parse cpuid[1] feature info
    cpu_features.x2apic = ecx & (1u << 21);
    cpu_features.tsc_deadline = ecx & (1u << 24);
    cpu_features.xsave = ecx & (1u << 26);

    if (ecx & (1u << 31)) {
        uint32_t hyp_limit;
        cpuid(0x40000000,
              &hyp_limit,
              &cpu_features.hypervisor.ebx,
              &cpu_features.hypervisor.ecx,
              &cpu_features.hypervisor.edx);
    }

    cpu_features.de = edx & (1u << 2);
    cpu_features.tsc = edx & (1u << 4);
    cpu_features.mce = edx & (1u << 7);
    cpu_features.xapic = edx & (1u << 9);
    cpu_features.global_pages = edx & (1u << 13);
    cpu_features.mca = edx & (1u << 14);
    cpu_features.pat = edx & (1u << 16);

    if (std_limit >= 7) {
        cpuid2(7, 0, &eax, &ebx, &ecx, &edx);
        cpu_features.fsgsbase = ebx & (1u << 0);
        cpu_features.smep = ebx & (1u << 7);
        cpu_features.smap = ebx & (1u << 20);

        cpu_features.umip = ecx & (1u << 2);
    }

    if (ext_limit >= 0x80000001) {
        cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
        cpu_features.nx = edx & (1u << 20);
        cpu_features.huge_1gb = edx & (1u << 26);
    }

    if (ext_limit >= 0x80000007) {
        cpuid(0x80000007, &eax, &ebx, &ecx, &edx);
        cpu_features.tsc_invariant = edx & (1u << 8);
    }

    if (ext_limit >= 0x80000008) {
        cpuid(0x80000008, &eax, &ebx, &ecx, &edx);

        int shift = eax & 0xff;
        if (shift > 52) shift = 52;
        cpu_features.paddr_mask = (1ul << shift) - 1;
    } else {
        cpu_features.paddr_mask = (1ul << 36) - 1;
    }
}

void init_cpu(cpu_t *cpu) {
    if (!cpu) {
        static cpu_t boot_cpu;
        __attribute__((aligned(16))) static unsigned char bsp_exc_stack[KERNEL_STACK_SIZE];

        cpu = &boot_cpu;
        cpu->tss.ist[0] = (uintptr_t)bsp_exc_stack + sizeof(bsp_exc_stack);
    }

    write_cr0((read_cr0() & ~CR0_CLEAR_MASK) | CR0_SET_MASK);
    size_t cr4 = read_cr4() | CR4_OSFXSR | CR4_OSXMMEXCPT;

    if (cpu_features.de) cr4 |= CR4_DE;
    if (cpu_features.tsc) cr4 &= ~CR4_TSD;
    if (cpu_features.fsgsbase) cr4 |= CR4_FSGSBASE;
    if (cpu_features.smep) cr4 |= CR4_SMEP;
    if (cpu_features.smap) cr4 |= CR4_SMAP;
    if (cpu_features.umip) cr4 |= CR4_UMIP;

    write_cr4(cr4);
    init_gdt(cpu);
    init_tss();
    setup_idt();
}
