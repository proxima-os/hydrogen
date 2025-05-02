#pragma once

#include "arch/memmap.h"
#include "kernel/compiler.h"
#include "mem/memmap.h"
#include "mem/pmap-flags.h"
#include "x86_64/cpu.h"
#include "x86_64/cr.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PTE_PRESENT (1ul << 0)
#define PTE_WRITABLE (1ul << 1)
#define PTE_USER (1ul << 2)
#define PTE_ACCESSED (1ul << 5)
#define PTE_DIRTY (1ul << 6)
#define PTE_HUGE (1ul << 7)
#define PTE_GLOBAL (1ul << 8)
#define PTE_NX (1ul << 63)

typedef uint64_t pte_t;

static inline void arch_switch_pt(void *target) {
    x86_64_write_cr3(virt_to_phys(target));
}

static inline void arch_switch_pt_init(void *target) {
    // Disable PGE before switching and reenable it afterwards.
    // This is done to ensure any stale global mappings are removed from the TLB.
    size_t cr4 = x86_64_read_cr4();
    if (x86_64_cpu_features.pge) x86_64_write_cr4(cr4 & ~X86_64_CR4_PGE);
    arch_switch_pt(target);
    if (x86_64_cpu_features.pge) x86_64_write_cr4(cr4 | X86_64_CR4_PGE);
}

static inline unsigned arch_pt_levels(void) {
    return x86_64_cpu_features.la57 ? 5 : 4;
}

static inline bool arch_pt_can_map_direct(unsigned level) {
    return level <= 1 || (level == 2 && x86_64_cpu_features.huge_1gb);
}

static inline unsigned arch_pt_entry_bits(unsigned level) {
    return level * 9 + 12;
}

static inline size_t arch_pt_get_index(uintptr_t virt, unsigned level) {
    return (virt >> arch_pt_entry_bits(level)) & 511;
}

static inline uintptr_t arch_pt_get_offset(uintptr_t virt) {
    return virt & 0xfff;
}

static inline pte_t arch_pt_read(void *table, unsigned level, size_t index) {
    return __atomic_load_n((uint64_t *)table + index, __ATOMIC_RELAXED);
}

static inline void arch_pt_write(void *table, unsigned level, size_t index, pte_t value) {
    __atomic_store_n((uint64_t *)table + index, value, __ATOMIC_RELAXED);
}

static inline pte_t arch_pt_create_edge(unsigned level, void *target) {
    return virt_to_phys(target) | PTE_DIRTY | PTE_ACCESSED | PTE_WRITABLE | PTE_PRESENT;
}

static inline pte_t arch_pt_create_leaf(unsigned level, uint64_t target, int flags, bool user) {
    pte_t pte = target | PTE_DIRTY | PTE_ACCESSED | PTE_PRESENT;
    if (level != 0) pte |= PTE_HUGE;

    if (flags & PMAP_WRITABLE) pte |= PTE_WRITABLE;
    if (!(flags & PMAP_EXECUTABLE) && x86_64_cpu_features.nx) pte |= PTE_NX;

    if (user) pte |= PTE_USER;
    else if (x86_64_cpu_features.pge) pte |= PTE_GLOBAL;

    return pte;
}

static inline bool arch_pt_is_edge(unsigned level, pte_t pte) {
    return level != 0 && (pte & PTE_HUGE) == 0;
}

static inline void *arch_pt_edge_target(unsigned level, pte_t pte) {
    ASSERT(arch_pt_is_edge(level, pte));
    return phys_to_virt((pte & ~0xfff) & x86_64_cpu_features.paddr_mask);
}

static inline uint64_t arch_pt_leaf_target(unsigned level, pte_t pte) {
    ASSERT(!arch_pt_is_edge(level, pte));
    return (pte & ~((1ul << arch_pt_entry_bits(level)) - 1)) & x86_64_cpu_features.paddr_mask;
}

static inline bool arch_pt_is_canonical(uintptr_t virt) {
    unsigned bits = cpu_vaddr_bits() - 1;
    uintptr_t top = virt >> bits;
    return top == 0 || top == (UINTPTR_MAX >> bits);
}
