#include "x86_64/cpu.h"
#include "arch/irq.h"
#include "cpu/cpudata.h"
#include "limine.h"
#include "sections.h"
#include "util/spinlock.h"
#include "x86_64/cpuid.h"
#include "x86_64/cr.h"
#include "x86_64/idt.h"
#include "x86_64/mca.h"
#include "x86_64/msr.h"
#include "x86_64/tss.h"
#include <stdint.h>

x86_64_cpu_features_t x86_64_cpu_features;

static size_t cr4_value = X86_64_CR4_OSXMMEXCEPT | X86_64_CR4_OSFXSR | X86_64_CR4_PAE;
static size_t efer_value = X86_64_MSR_EFER_LME | X86_64_MSR_EFER_SCE;

static LIMINE_REQ const struct limine_paging_mode_request pmode_req = {
        .id = LIMINE_PAGING_MODE_REQUEST,
        .revision = 1,
        .mode = LIMINE_PAGING_MODE_X86_64_5LVL,
        .min_mode = LIMINE_PAGING_MODE_X86_64_4LVL,
        .max_mode = LIMINE_PAGING_MODE_X86_64_5LVL,
};

void x86_64_cpu_detect(void) {
    cr4_value |= x86_64_read_cr4() & X86_64_CR4_LA57;

    x86_64_cpu_features_t *feat = &x86_64_cpu_features;
    feat->paddr_mask = (1ull << 36) - 1;

    unsigned eax, ebx, ecx, edx;
    cpuid(0, &feat->cpuid_low, &feat->cpu_vendor.ebx, &feat->cpu_vendor.ecx, &feat->cpu_vendor.edx);

    if (feat->cpuid_low >= 1) {
        cpuid(1, &eax, &ebx, &ecx, &edx);

        feat->pcid = ecx & (1u << 17);
        feat->x2apic = ecx & (1u << 21);
        feat->tsc_deadline = ecx & (1u << 24);
        feat->xsave = ecx & (1u << 26);
        feat->hypervisor = ecx & (1u << 31);
        feat->de = edx & (1u << 2);
        feat->mce = edx & (1u << 7);
        feat->apic = edx & (1u << 9);
        feat->pge = edx & (1u << 13);
        feat->mca = edx & (1u << 14);
        feat->pat = edx & (1u << 16);

        if (feat->hypervisor) {
            cpuid(0x40000000, &feat->cpuid_hyp, &feat->hyp_vendor.ebx, &feat->hyp_vendor.ecx, &feat->hyp_vendor.edx);
        }
    }

    if (feat->cpuid_low >= 7) {
        unsigned leaf7_max;
        cpuid2(7, 0, &leaf7_max, &ebx, &ecx, &edx);

        feat->fsgsbase = ebx & (1u << 0);
        feat->smep = ebx & (1u << 7);
        feat->invpcid = ebx & (1u << 10);
        feat->smap = ebx & (1u << 20);
        feat->umip = ecx & (1u << 2);
    }

    cpuid(0x80000000, &feat->cpuid_high, &ebx, &ecx, &edx);

    if (feat->cpuid_high >= 0x80000001) {
        cpuid(0x80000001, &eax, &ebx, &ecx, &edx);

        feat->nx = edx & (1u << 20);
        feat->huge_1gb = edx & (1u << 26);
    }

    if (feat->cpuid_high >= 0x80000007) {
        cpuid(0x80000007, &eax, &ebx, &ecx, &edx);

        feat->tsc_invariant = edx & (1u << 8);
    }

    if (feat->cpuid_high >= 0x80000008) {
        cpuid(0x80000008, &eax, &ebx, &ecx, &edx);
        feat->paddr_mask = (1ull << (eax & 0xff)) - 1;
        feat->invlpgb = ebx & (1u << 3);
    }

    feat->la57 = cr4_value & X86_64_CR4_LA57;

    // NOTE: PCIDE and PGE are only enabled later to ensure there are no stale TLB entries.
    if (feat->xsave) cr4_value |= X86_64_CR4_OSXSAVE;
    if (feat->de) cr4_value |= X86_64_CR4_DE;
    if (feat->fsgsbase) cr4_value |= X86_64_CR4_FSGSBASE;
    if (feat->smep) cr4_value |= X86_64_CR4_SMEP;
    if (feat->smap) cr4_value |= X86_64_CR4_SMAP;
    if (feat->umip) cr4_value |= X86_64_CR4_UMIP;
    if (feat->nx) efer_value |= X86_64_MSR_EFER_NXE;
}

static uint64_t gdt[7] = {
        0,                // reserved
        0x209b0000000000, // kernel code
        0x40930000000000, // kernel data
        0x40f30000000000, // user data
        0x40fb0000000000, // user code
        0,                // tss low
        0,                // tss high
};
static spinlock_t gdt_lock;

static void init_gdt(cpu_t *self) {
    struct {
        uint16_t limit;
        void *base;
    } __attribute__((packed)) desc = {sizeof(gdt) - 1, gdt};
    asm("   lgdt %0 \n\t"
        "   lea 1f(%%rip), %%rax \n\t"
        "   pushq %1 \n\t"
        "   pushq %%rax \n\t"
        "   lretq \n\t"
        "1: xor %%eax, %%eax \n\t"
        "   mov %%eax, %%ds \n\t"
        "   mov %%eax, %%es \n\t"
        "   mov %%eax, %%fs \n\t"
        "   mov %%eax, %%gs \n\t"
        "   mov %%eax, %%ss \n\t"
        "   lldt %%ax" ::"m"(desc),
        "i"(X86_64_KERN_CS)
        : "rax");
    x86_64_wrmsr(X86_64_MSR_GS_BASE, (uintptr_t)self);

    x86_64_tss_t *tss = &self->arch.tss;
    tss->iopb_base = sizeof(*tss);

    for (size_t i = 0; i < 7; i++) {
        uintptr_t stack = tss->ist[i];
        if (!stack) continue;

        stack = (stack - 16) & ~15;
        *(void **)stack = self;
        tss->ist[i] = stack;
    }

    uintptr_t tss_base = (uintptr_t)tss;
    uint64_t tss_low = (sizeof(*tss) - 1) | ((tss_base & 0xffffff) << 16) | ((tss_base & 0xff000000) << 32) |
                       (0x89ull << 40);
    uint64_t tss_high = tss_base >> 32;

    irq_state_t state = spin_acq(&gdt_lock);
    gdt[X86_64_SEL_TSS / 8] = tss_low;
    gdt[X86_64_SEL_TSS / 8 + 1] = tss_high;
    asm("ltr %w0" ::"r"(X86_64_SEL_TSS));
    spin_rel(&gdt_lock, state);
}

void x86_64_cpu_init(cpu_t *self) {
    x86_64_write_cr0(
            X86_64_CR0_PG | X86_64_CR0_AM | X86_64_CR0_WP | X86_64_CR0_NE | X86_64_CR0_ET | X86_64_CR0_MP |
            X86_64_CR0_PE
    );
    x86_64_write_cr4(cr4_value);
    x86_64_wrmsr(X86_64_MSR_EFER, efer_value);

    self->arch.self = self;
    init_gdt(self);
    x86_64_idt_init();
    x86_64_mca_init();
}
