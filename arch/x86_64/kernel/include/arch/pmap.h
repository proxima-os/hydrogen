#pragma once

#include "arch/memmap.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/memmap.h"
#include "mem/pmap-flags.h"
#include "x86_64/cpu.h"
#include "x86_64/cr.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define X86_64_PTE_PRESENT (1ul << 0)
#define X86_64_PTE_WRITABLE (1ul << 1)
#define X86_64_PTE_USER (1ul << 2)
#define X86_64_PTE_ACCESSED (1ul << 5)
#define X86_64_PTE_DIRTY (1ul << 6)
#define X86_64_PTE_HUGE (1ul << 7)
#define X86_64_PTE_GLOBAL (1ul << 8)
#define X86_64_PTE_NX (1ul << 63)

_Static_assert(PAGE_SHIFT >= 12, "PAGE_SHIFT too small");

/* the highest value arch_pt_levels() can return */
#define ARCH_PT_MAX_LEVELS 5

typedef uint64_t pte_t;

/* switch to the target table and ensure there are no stale tlb entries */
static inline void arch_switch_pt(void *target) {
    x86_64_write_cr3(virt_to_phys(target));
}

/* the same as arch_switch_pt, except do any extra processing that is required for the first switch */
static inline void arch_switch_pt_init(void *target) {
    // Disable PGE before switching and reenable it afterwards.
    // This is done to ensure any stale global mappings are removed from the TLB.
    size_t cr4 = x86_64_read_cr4();
    if (x86_64_cpu_features.pge) x86_64_write_cr4(cr4 & ~X86_64_CR4_PGE);
    arch_switch_pt(target);
    if (x86_64_cpu_features.pge) x86_64_write_cr4(cr4 | X86_64_CR4_PGE);
}

/* return the number of page table levels. must be constant. */
static inline unsigned arch_pt_levels(void) {
    return x86_64_cpu_features.la57 ? 5 : 4;
}

/* return true if pages can be mapped directly in the given level */
static inline bool arch_pt_can_map_direct(unsigned level) {
    return level <= 1 || (level == 2 && x86_64_cpu_features.huge_1gb);
}

/* return the number of virtual address bits that vary within a single entry for the given level */
static inline unsigned arch_pt_entry_bits(unsigned level) {
    return level * 9 + 12;
}

/* return the page table index for a given virtual address and page table level */
static inline size_t arch_pt_get_index(uintptr_t virt, unsigned level) {
    return (virt >> arch_pt_entry_bits(level)) & 511;
}

/* return the offset into a single mapping. if value is a multiple of PAGE_SIZE, this must return 0. */
static inline uint64_t arch_pt_get_offset(uint64_t value) {
    return value & 0xfff;
}

/* reads an entry from the given page table */
static inline pte_t arch_pt_read(void *table, unsigned level, size_t index) {
    return __atomic_load_n((uint64_t *)table + index, __ATOMIC_RELAXED);
}

/* writes an entry to the given page table */
static inline void arch_pt_write(void *table, unsigned level, size_t index, pte_t value) {
    __atomic_store_n((uint64_t *)table + index, value, __ATOMIC_RELAXED);
}

/* create a pte that points to another page table */
static inline pte_t arch_pt_create_edge(unsigned level, void *target) {
    ASSERT(level != 0);
    return virt_to_phys(target) | X86_64_PTE_ACCESSED | X86_64_PTE_WRITABLE | X86_64_PTE_PRESENT;
}

/* create a pte that maps a page */
static inline pte_t arch_pt_create_leaf(unsigned level, uint64_t target, int flags, bool user) {
    pte_t pte = target | X86_64_PTE_DIRTY | X86_64_PTE_ACCESSED | X86_64_PTE_PRESENT;
    if (level != 0) pte |= X86_64_PTE_HUGE;

    if (flags & PMAP_WRITABLE) pte |= X86_64_PTE_WRITABLE;
    if (!(flags & PMAP_EXECUTABLE) && x86_64_cpu_features.nx) pte |= X86_64_PTE_NX;

    if (user) pte |= X86_64_PTE_USER;
    else if (x86_64_cpu_features.pge) pte |= X86_64_PTE_GLOBAL;

    return pte;
}

/* return true if the given pte points to another page table */
static inline bool arch_pt_is_edge(unsigned level, pte_t pte) {
    return level != 0 && (pte & X86_64_PTE_HUGE) == 0;
}

/* get the page table the given pte points to */
static inline void *arch_pt_edge_target(unsigned level, pte_t pte) {
    ASSERT(arch_pt_is_edge(level, pte));
    return phys_to_virt((pte & ~0xfff) & x86_64_cpu_features.paddr_mask);
}

/* get the physical address the given pte points to */
static inline uint64_t arch_pt_leaf_target(unsigned level, pte_t pte) {
    ASSERT(!arch_pt_is_edge(level, pte));
    return (pte & ~((1ul << arch_pt_entry_bits(level)) - 1)) & x86_64_cpu_features.paddr_mask;
}

/* return true if the given address is canonical */
static inline bool arch_pt_is_canonical(uintptr_t virt) {
    unsigned bits = cpu_vaddr_bits() - 1;
    uintptr_t top = virt >> bits;
    return top == 0 || top == (UINTPTR_MAX >> bits);
}
