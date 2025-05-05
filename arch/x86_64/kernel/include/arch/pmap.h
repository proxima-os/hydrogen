#pragma once

#include "arch/memmap.h"
#include "cpu/cpudata.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/memmap.h"
#include "mem/pmap-protos.h"
#include "proc/sched.h"
#include "string.h"
#include "x86_64/cpu.h"
#include "x86_64/cr.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define X86_64_PTE_PRESENT (1ul << 0)
#define X86_64_PTE_WRITABLE (1ul << 1)
#define X86_64_PTE_USER (1ul << 2)
#define X86_64_PTE_WRITE_THROUGH (1ul << 3)
#define X86_64_PTE_CACHE_DISABLE (1ul << 4)
#define X86_64_PTE_ACCESSED (1ul << 5)
#define X86_64_PTE_DIRTY (1ul << 6)
#define X86_64_PTE_HUGE (1ul << 7)
#define X86_64_PTE_GLOBAL (1ul << 8)
#define X86_64_PTE_ANON (1ul << 9)
#define X86_64_PTE_NX (1ul << 63)

#define X86_64_PTE_PAT(x) ((((x) & 4) << 5) | (((x) & 3) << 3))
#define X86_64_PTE_PAT_HUGE(x) ((((x) & 4) << 10) | (((x) & 3) << 3))
#define X86_64_PTE_PAT_EXTRACT(x) ((((x) & 0x80) >> 5) | (((x) & 0x18) >> 3))
#define X86_64_PTE_PAT_HUGE_EXTRACT(x) ((((x) & 0x1000) >> 10) | (((x) & 0x18) >> 3))
#define X86_64_PAT_WT 1
#define X86_64_PAT_UC 3
#define X86_64_PAT_WC 5

_Static_assert(PAGE_SHIFT >= 12, "PAGE_SHIFT too small");

#define ARCH_PT_MAX_LEVELS 5
#define ARCH_PT_PREPARE_PTE 0xfedcba98765210

static inline int arch_pt_max_asid(void) {
    return x86_64_cpu_features.pcid ? 4095 : 0;
}

static inline void arch_pt_switch(void *target, int asid, bool current) {
    size_t cr3_value = virt_to_phys(target);

    if (x86_64_cpu_features.pcid && current) {
        // don't clear the tlb
        cr3_value |= 1ul << 63;
    }

    if (asid >= 0) {
        cr3_value |= asid;
        this_cpu_write_tl(arch.current_pcid, asid);
    }

    x86_64_write_cr3(cr3_value);
}

static inline void arch_pt_switch_init(void *target, int asid, bool current) {
    arch_pt_switch(target, asid, current);

    size_t cr4 = x86_64_read_cr4();
    if (x86_64_cpu_features.pcid) cr4 |= X86_64_CR4_PCIDE;
    if (x86_64_cpu_features.pge) cr4 |= X86_64_CR4_PGE;
    x86_64_write_cr4(cr4);
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

static inline uint64_t arch_pt_get_offset(uint64_t value) {
    return value & 0xfff;
}

static inline pte_t arch_pt_read(void *table, unsigned level, size_t index) {
    return __atomic_load_n((uint64_t *)table + index, __ATOMIC_RELAXED);
}

static inline void arch_pt_write(void *table, unsigned level, size_t index, pte_t value) {
    __atomic_store_n((uint64_t *)table + index, value, __ATOMIC_RELAXED);
}

static inline pte_t arch_pt_create_edge(unsigned level, void *target) {
    ASSERT(level != 0);
    return virt_to_phys(target) | X86_64_PTE_ACCESSED | X86_64_PTE_WRITABLE | X86_64_PTE_PRESENT;
}

static inline pte_t arch_pt_create_leaf(unsigned level, uint64_t target, int flags) {
    pte_t pte = target | X86_64_PTE_DIRTY | X86_64_PTE_ACCESSED | X86_64_PTE_PRESENT;
    if (level != 0) pte |= X86_64_PTE_HUGE;

    if (flags & PMAP_WRITABLE) pte |= X86_64_PTE_WRITABLE;
    if (!(flags & PMAP_EXECUTABLE) && x86_64_cpu_features.nx) pte |= X86_64_PTE_NX;

    if (flags & PMAP_USER) pte |= X86_64_PTE_USER;
    else if (x86_64_cpu_features.pge) pte |= X86_64_PTE_GLOBAL;

    if (x86_64_cpu_features.pat) {
        int index;

        switch (flags & PMAP_CACHE_MASK) {
        case 0: index = 0; break;
        case PMAP_CACHE_WT: index = X86_64_PAT_WT; break;
        case PMAP_CACHE_WC: index = X86_64_PAT_WC; break;
        case PMAP_CACHE_UC: index = X86_64_PAT_UC; break;
        default: UNREACHABLE();
        }

        pte |= level != 0 ? X86_64_PTE_PAT_HUGE(index) : X86_64_PTE_PAT(index);
    } else {
        switch (flags & PMAP_CACHE_MASK) {
        case 0: break;
        case PMAP_CACHE_WT:
        case PMAP_CACHE_WC: pte |= X86_64_PTE_WRITE_THROUGH; break;
        case PMAP_CACHE_UC: pte |= X86_64_PTE_CACHE_DISABLE | X86_64_PTE_WRITE_THROUGH; break;
        default: UNREACHABLE();
        }
    }

    return pte;
}

static inline bool arch_pt_is_edge(unsigned level, pte_t pte) {
    ASSERT(pte & X86_64_PTE_PRESENT);
    return level != 0 && (pte & X86_64_PTE_HUGE) == 0;
}

static inline void *arch_pt_edge_target(unsigned level, pte_t pte) {
    ASSERT(arch_pt_is_edge(level, pte));
    return phys_to_virt((pte & ~0xfff) & x86_64_cpu_features.paddr_mask);
}

static inline uint64_t arch_pt_leaf_target(unsigned level, pte_t pte) {
    ASSERT(!arch_pt_is_edge(level, pte));
    return (pte & ~((1ul << arch_pt_entry_bits(level)) - 1)) & x86_64_cpu_features.paddr_mask;
}

static inline int arch_pt_get_leaf_flags(unsigned level, pte_t pte) {
    ASSERT(!arch_pt_is_edge(level, pte));
    int flags = PMAP_READABLE;

    if (pte & X86_64_PTE_WRITABLE) flags |= PMAP_WRITABLE;
    if (pte & X86_64_PTE_ANON) flags |= PMAP_ANONYMOUS;
    if (!x86_64_cpu_features.nx || (pte & X86_64_PTE_NX) == 0) flags |= PMAP_EXECUTABLE;

    if (x86_64_cpu_features.pat) {
        int index = level != 0 ? X86_64_PTE_PAT_HUGE_EXTRACT(pte) : X86_64_PTE_PAT_EXTRACT(pte);

        switch (index) {
        case 0: break;
        case X86_64_PAT_WT: flags |= PMAP_CACHE_WT; break;
        case X86_64_PAT_UC: flags |= PMAP_CACHE_UC; break;
        case X86_64_PAT_WC: flags |= PMAP_CACHE_WC; break;
        default: UNREACHABLE();
        }
    } else {
        if (flags & X86_64_PTE_CACHE_DISABLE) flags |= PMAP_CACHE_UC;
        else if (flags & X86_64_PTE_WRITE_THROUGH) flags |= PMAP_CACHE_WT;
    }

    return flags;
}

static inline bool arch_pt_is_canonical(uintptr_t virt) {
    unsigned bits = cpu_vaddr_bits() - 1;
    uintptr_t top = virt >> bits;
    return top == 0 || top == (UINTPTR_MAX >> bits);
}

static inline bool arch_pt_new_leaf_needs_flush(void) {
    return false;
}

static inline bool arch_pt_new_edge_needs_flush(void) {
    return false;
}

static inline bool arch_pt_flush_can_broadcast(void) {
    return x86_64_cpu_features.invlpgb;
}

static inline bool arch_pt_flush_edge_coarse(void) {
    return true;
}

#define X86_64_INVPCID_SINGLE_ADDRESS 0
#define X86_64_INVPCID_SINGLE_CONTEXT 1
#define X86_64_INVPCID_ALL_CONTEXTS_GLOBAL 2

static inline void x86_64_invlpg(uintptr_t virt) {
    asm("invlpg (%0)" ::"r"(virt) : "memory");
}

static inline void x86_64_invpcid(uintptr_t virt, unsigned long asid, unsigned long type) {
    struct {
        uint64_t d[2];
    } desc = {{asid, virt}};
    asm("invpcid %0, %1" ::"m"(desc), "r"(type) : "memory");
}

static inline void x86_64_invlpg_asid(uintptr_t virt, void *table, int asid) {
    if (asid < 0 || asid == this_cpu_read(arch.current_pcid)) {
        x86_64_invlpg(virt);
    } else {
        // invplg only flushes in the current pcid, so we need to switch to the other one temporarily
        preempt_state_t state = preempt_lock();
        size_t cr3 = x86_64_read_cr3();
        x86_64_write_cr3(virt_to_phys(table) | asid | (1ul << 63));
        x86_64_invlpg(virt);
        x86_64_write_cr3(cr3 | (1ul << 63));
        preempt_unlock(state);
    }
}

#define X86_64_INVLPGB_ADDRESS (1 << 0)
#define X86_64_INVLPGB_PCID (1 << 1)
#define X86_64_INVLPGB_GLOBAL (1 << 3)
#define X86_64_INVLPGB_ONLY_LEAF (1 << 4)

static inline void x86_64_invlpgb(uintptr_t virt, int asid, int type) {
    asm("invlpgb" ::"a"((virt & ~0xfff) | type), "d"(asid));
}

static inline void arch_pt_flush_leaf(uintptr_t virt, void *table, int asid, bool broadcast, bool current) {
    if (broadcast) {
        if (x86_64_cpu_features.invlpgb) {
            if (asid >= 0) {
                x86_64_invlpgb(virt, asid, X86_64_INVLPGB_ADDRESS | X86_64_INVLPGB_PCID | X86_64_INVLPGB_ONLY_LEAF);
            }

            x86_64_invlpgb(virt, 0, X86_64_INVLPGB_ADDRESS | X86_64_INVLPGB_ONLY_LEAF | X86_64_INVLPGB_GLOBAL);
        }
    } else if (current) {
        if (asid >= 0 && x86_64_cpu_features.invpcid) {
            x86_64_invpcid(virt, asid, X86_64_INVPCID_SINGLE_ADDRESS);
        }

        x86_64_invlpg_asid(virt, table, asid);
    }
}

static inline void arch_pt_flush_edge(uintptr_t virt, void *table, int asid, bool broadcast, bool current) {
    if (broadcast) {
        if (x86_64_cpu_features.invlpgb) {
            if (asid >= 0) {
                x86_64_invlpgb(virt, asid, X86_64_INVLPGB_ADDRESS | X86_64_INVLPGB_PCID);
            }

            x86_64_invlpgb(virt, 0, X86_64_INVLPGB_ADDRESS | X86_64_INVLPGB_GLOBAL);
        }
    } else if (current) {
        if (asid >= 0 || !x86_64_cpu_features.pcid) {
            x86_64_invlpg_asid(0, table, asid);
        } else {
            // We need to flush edge TLB entries for all PCIDs. This can only be done by flipping
            // PGE or clearing PCIDE. We prefer flipping PGE, since clearing PCIDE can only be done
            // when the current PCID is 0 (otherwise we might accidentally set PCD/PWT).

            preempt_state_t state = preempt_lock();
            size_t cr4 = x86_64_read_cr4();

            if (x86_64_cpu_features.pge) {
                x86_64_write_cr4(cr4 & ~X86_64_CR4_PGE);
                x86_64_write_cr4(cr4);
            } else {
                size_t cr3 = x86_64_read_cr3();
                x86_64_write_cr3(virt_to_phys(table));
                x86_64_write_cr4(cr4 & ~X86_64_CR4_PCIDE);
                x86_64_write_cr4(cr4);
                x86_64_write_cr3(cr3);
            }

            preempt_unlock(state);
        }
    }
}

static inline void arch_pt_flush(void *table, int asid) {
    if (asid >= 0) {
        if (x86_64_cpu_features.invpcid) {
            x86_64_invpcid(0, asid, X86_64_INVPCID_SINGLE_CONTEXT);
        } else {
            x86_64_write_cr3(virt_to_phys(table) | asid);
        }
    } else if (!x86_64_cpu_features.pge) {
        x86_64_write_cr3(virt_to_phys(table));
    } else if (x86_64_cpu_features.invpcid) {
        x86_64_invpcid(0, 0, X86_64_INVPCID_ALL_CONTEXTS_GLOBAL);
    } else {
        size_t cr4 = x86_64_read_cr4();
        x86_64_write_cr4(cr4 & ~X86_64_CR4_PGE);
        x86_64_write_cr4(cr4);
    }
}

static inline void arch_pt_flush_wait(void) {
    if (x86_64_cpu_features.invlpgb) asm("tlbsync" ::: "memory");
}

static inline uintptr_t arch_pt_max_user_addr(void) {
    return (1ul << (cpu_vaddr_bits() - 1)) - 0x1001;
}

static inline size_t arch_pt_max_index(unsigned level) {
    return 511;
}

static inline bool arch_pt_init_table(void *table, unsigned level) {
    memset(table, 0, PAGE_SIZE);
    return true;
}

static inline bool arch_pt_change_permissions(pte_t *pte, unsigned level, int new_flags) {
    pte_t value = *pte;
    bool need_flush = false;

    ASSERT(!arch_pt_is_edge(level, value));

    if (new_flags & PMAP_WRITABLE) {
        value |= X86_64_PTE_WRITABLE;
    } else if (value & X86_64_PTE_WRITABLE) {
        value &= ~X86_64_PTE_WRITABLE;
        need_flush = true;
    }

    if (x86_64_cpu_features.nx) {
        if (new_flags & PMAP_EXECUTABLE) {
            value &= ~X86_64_PTE_NX;
        } else if (!(value & X86_64_PTE_NX)) {
            value |= X86_64_PTE_NX;
            need_flush = true;
        }
    }

    *pte = value;
    return need_flush;
}
