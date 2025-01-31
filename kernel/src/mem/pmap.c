#include "mem/pmap.h"
#include "asm/cr.h"
#include "asm/tlb.h"
#include "cpu/cpu.h"
#include "hydrogen/error.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "limine.h"
#include "mem/kmalloc.h"
#include "mem/pmm.h"
#include "sections.h"
#include "string.h"
#include "util/panic.h"
#include "util/spinlock.h"
#include <stdint.h>

// TODO: Separate address spaces
// TODO: TLB shootdown

#define PTE_PRESENT 1
#define PTE_WRITABLE 2
#define PTE_USERSPACE 4
#define PTE_ACCESSED 0x20
#define PTE_DIRTY 0x40
#define PTE_HUGE 0x80
#define PTE_GLOBAL 0x100
#define PTE_ALLOCATED 0x200
#define PTE_ADDR_MASK 0xffffffffff000
#define PTE_NX 0x8000000000000000

#define TABLE_FLAGS (PTE_PRESENT | PTE_WRITABLE | PTE_ACCESSED)

#define PT_SIZE 0x1000

static uint64_t *kernel_pt;
static spinlock_t kernel_pt_lock;

static enum {
    PT_4LEVEL,
    PT_5LEVEL,
} pt_style;

void init_pmap(void) {
    static LIMINE_REQ struct limine_paging_mode_request pmode_req = {
            .id = LIMINE_PAGING_MODE_REQUEST,
            .mode = LIMINE_PAGING_MODE_X86_64_5LVL,
            .min_mode = LIMINE_PAGING_MODE_X86_64_4LVL,
            .max_mode = LIMINE_PAGING_MODE_X86_64_5LVL,
    };

    kernel_pt = kmalloc(PT_SIZE);
    if (unlikely(!kernel_pt)) panic("failed to allocate kernel page table");
    memset(kernel_pt, 0, PT_SIZE);

    if (pmode_req.response) {
        switch (pmode_req.response->mode) {
        case LIMINE_PAGING_MODE_X86_64_4LVL: pt_style = PT_4LEVEL; break;
        case LIMINE_PAGING_MODE_X86_64_5LVL: pt_style = PT_5LEVEL; break;
        default: panic("invalid paging mode: %U", pmode_req.response->mode);
        }
    } else {
        pt_style = PT_4LEVEL;
    }
}

void pmap_init_switch(void) {
    if (cpu_features.global_pages) {
        size_t cr4 = read_cr4();
        write_cr4(cr4 & ~CR4_PGE);
        write_cr3(virt_to_phys(kernel_pt));
        write_cr4(cr4 | CR4_PGE);
    } else {
        write_cr3(virt_to_phys(kernel_pt));
    }
}

static bool can_map_direct(unsigned level) {
    return level < 2 || (level == 2 && cpu_features.huge_1gb);
}

static bool is_kernel_memory(uintptr_t virt) {
    return virt & (1ul << 63);
}

static hydrogen_error_t do_map(uint64_t *table, unsigned level, uintptr_t virt, uint64_t pte, size_t size) {
    unsigned bits = level * 9 + 12;
    size_t index = (virt >> bits) & 511;
    size_t entry_size = 1ul << bits;
    size_t entry_mask = (entry_size - 1) & PTE_ADDR_MASK;

    while (size > 0) {
        uintptr_t offset = virt & entry_mask;

        if (level == 0 || (offset == 0 && (pte & entry_mask) == 0 && size >= entry_size && can_map_direct(level))) {
            ASSERT(table[index] == 0);

            uint64_t entry = pte;
            if (level != 0) entry |= ((entry & PTE_HUGE) << 5) | PTE_HUGE; // the PAT bit in level 0 is the HUGE bit

            __atomic_store_n(&table[index++], entry, __ATOMIC_RELAXED);
            virt += entry_size;
            pte += entry_size;
            size -= entry_size;
            continue;
        }

        uint64_t entry = __atomic_load_n(&table[index], __ATOMIC_RELAXED);
        uint64_t *child;

        if (unlikely(entry == 0)) {
            child = kmalloc(PT_SIZE);
            if (unlikely(!child)) return HYDROGEN_OUT_OF_MEMORY;
            memset(child, 0, PT_SIZE);
            __atomic_store_n(&table[index], virt_to_phys(child) | TABLE_FLAGS, __ATOMIC_RELAXED);
        } else {
            ASSERT((entry & PTE_HUGE) == 0);
            child = phys_to_virt(entry & PTE_ADDR_MASK);
        }

        size_t cur = entry_size - offset;
        if (cur > size) cur = size;

        hydrogen_error_t error = do_map(child, level - 1, virt, pte, cur);
        if (unlikely(error)) return error;

        index += 1;
        virt += cur;
        pte += cur;
        size -= cur;
    }

    return HYDROGEN_SUCCESS;
}

hydrogen_error_t map_kernel_memory(uintptr_t virt, uint64_t phys, size_t size, int flags, cache_mode_t mode) {
    ASSERT((virt & PAGE_MASK) == 0);
    ASSERT((phys & PAGE_MASK) == 0);
    ASSERT((size & PAGE_MASK) == 0);
    ASSERT(size != 0);
    ASSERT((virt + size - 1) >= virt);
    ASSERT(is_kernel_memory(virt));
    ASSERT((phys & ~cpu_features.paddr_mask) == 0);

    uint64_t pte = PTE_PRESENT | PTE_ACCESSED | PTE_DIRTY | ((mode & 3) << 3) | ((mode & 4) << 5) | phys;
    if (flags & PMAP_WRITE) pte |= PTE_WRITABLE;
    if ((flags & PMAP_EXEC) == 0 && cpu_features.nx) pte |= PTE_NX;

    spin_lock_noirq(&kernel_pt_lock);
    hydrogen_error_t result;
    switch (pt_style) {
    case PT_4LEVEL: result = do_map(kernel_pt, 3, virt, pte, size); break;
    case PT_5LEVEL: result = do_map(kernel_pt, 4, virt, pte, size); break;
    }
    spin_unlock_noirq(&kernel_pt_lock);
    return result;
}

static hydrogen_error_t do_alloc(uint64_t *table, unsigned level, uintptr_t virt, uint64_t pte, size_t size) {
    unsigned bits = level * 9 + 12;
    size_t index = (virt >> bits) & 511;
    size_t entry_size = 1ul << bits;
    size_t entry_mask = entry_size - 1;

    while (size > 0) {
        if (level == 0) {
            ASSERT(table[index] == 0);

            __atomic_store_n(&table[index++], pte | page_to_phys(pmm_alloc()), __ATOMIC_RELAXED);
            virt += entry_size;
            pte += entry_size;
            size -= entry_size;
            continue;
        }

        uint64_t entry = __atomic_load_n(&table[index], __ATOMIC_RELAXED);
        uint64_t *child;

        if (unlikely(entry == 0)) {
            child = kmalloc(PT_SIZE);
            if (unlikely(!child)) return HYDROGEN_OUT_OF_MEMORY;
            __atomic_store_n(&table[index], virt_to_phys(child) | TABLE_FLAGS, __ATOMIC_RELAXED);
        } else {
            ASSERT((entry & PTE_HUGE) == 0);
            child = phys_to_virt(entry & PTE_ADDR_MASK);
        }

        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        hydrogen_error_t error = do_alloc(child, level - 1, virt, pte, cur);
        if (unlikely(error)) return error;

        index += 1;
        virt += cur;
        pte += cur;
        size -= cur;
    }

    return HYDROGEN_SUCCESS;
}

hydrogen_error_t alloc_kernel_memory(uintptr_t virt, size_t size, int flags) {
    ASSERT((virt & PAGE_MASK) == 0);
    ASSERT((size & PAGE_MASK) == 0);
    ASSERT(size != 0);
    ASSERT((virt + size - 1) >= virt);
    ASSERT(is_kernel_memory(virt));

    uint64_t pte = PTE_PRESENT | PTE_ACCESSED | PTE_DIRTY | PTE_ALLOCATED;
    if (flags & PMAP_WRITE) pte |= PTE_WRITABLE;
    if ((flags & PMAP_EXEC) == 0 && cpu_features.nx) pte |= PTE_NX;

    spin_lock_noirq(&kernel_pt_lock);
    hydrogen_error_t result;
    switch (pt_style) {
    case PT_4LEVEL: result = do_alloc(kernel_pt, 3, virt, pte, size); break;
    case PT_5LEVEL: result = do_alloc(kernel_pt, 4, virt, pte, size); break;
    }
    spin_unlock_noirq(&kernel_pt_lock);
    return result;
}

static void do_remap(uint64_t *table, unsigned level, uintptr_t virt, size_t size, uint64_t flags) {
    unsigned bits = level * 9 + 12;
    size_t index = (virt >> bits) & 511;
    size_t entry_size = 1ul << bits;
    size_t entry_mask = entry_size - 1;

    while (size > 0) {
        uint64_t entry = __atomic_load_n(&table[index], __ATOMIC_RELAXED);
        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        if (likely(entry != 0)) {
            if (level == 0 || (entry & PTE_HUGE) != 0) {
                uint64_t new_entry = (entry & ~(PTE_NX | PTE_WRITABLE)) | flags;

                if (likely(entry != new_entry)) {
                    __atomic_store_n(&table[index], new_entry, __ATOMIC_RELAXED);
                    invlpg(virt);
                }
            } else {
                ASSERT((entry & PTE_HUGE) == 0);
                do_remap(phys_to_virt(entry & PTE_ADDR_MASK), level - 1, virt, cur, flags);
            }
        }

        index += 1;
        virt += cur;
        size -= cur;
    }
}

void remap_memory(uintptr_t virt, size_t size, int flags) {
    ASSERT((virt & PAGE_MASK) == 0);
    ASSERT((size & PAGE_MASK) == 0);
    ASSERT(size != 0);
    ASSERT((virt + size - 1) >= virt);
    ASSERT(is_kernel_memory(virt) == is_kernel_memory(virt + size - 1));

    uint64_t pte = 0;
    if (flags & PMAP_WRITE) pte |= PTE_WRITABLE;
    if ((flags & PMAP_EXEC) == 0 && cpu_features.nx) pte |= PTE_NX;

    spin_lock_noirq(&kernel_pt_lock);
    switch (pt_style) {
    case PT_4LEVEL: do_remap(kernel_pt, 3, virt, size, pte); break;
    case PT_5LEVEL: do_remap(kernel_pt, 4, virt, size, pte); break;
    }
    spin_unlock_noirq(&kernel_pt_lock);
}

static void do_unmap(uint64_t *table, unsigned level, uintptr_t virt, size_t size) {
    unsigned bits = level * 9 + 12;
    size_t index = (virt >> bits) & 511;
    size_t entry_size = 1ul << bits;
    size_t entry_mask = entry_size - 1;

    while (size > 0) {
        uint64_t entry = __atomic_load_n(&table[index], __ATOMIC_RELAXED);
        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        if (likely(entry != 0)) {
            if (level == 0 || (entry & PTE_HUGE) != 0) {
                __atomic_store_n(&table[index], 0, __ATOMIC_RELAXED);
                invlpg(virt);
            } else {
                ASSERT((entry & PTE_HUGE) == 0);
                do_unmap(phys_to_virt(entry & PTE_ADDR_MASK), level - 1, virt, cur);
            }
        }

        index += 1;
        virt += cur;
        size -= cur;
    }
}

void unmap_memory(uintptr_t virt, size_t size) {
    ASSERT((virt & PAGE_MASK) == 0);
    ASSERT((size & PAGE_MASK) == 0);
    ASSERT(size != 0);
    ASSERT((virt + size - 1) >= virt);
    ASSERT(is_kernel_memory(virt) == is_kernel_memory(virt + size - 1));

    spin_lock_noirq(&kernel_pt_lock);
    switch (pt_style) {
    case PT_4LEVEL: do_unmap(kernel_pt, 3, virt, size); break;
    case PT_5LEVEL: do_unmap(kernel_pt, 4, virt, size); break;
    }
    spin_unlock_noirq(&kernel_pt_lock);
}
