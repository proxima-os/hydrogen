#include "mem/pmap.h"
#include "arch/memmap.h"
#include "arch/pmap.h"
#include "cpu/smp.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/memmap.h"
#include "proc/mutex.h"
#include "proc/sched.h"
#include "string.h"
#include <stddef.h>
#include <stdint.h>

static void *kernel_page_table;
static mutex_t kernel_pt_lock;
static bool kernel_pt_switched;

typedef struct {
    void *table;
    int asid;
    bool current : 1;
    bool broadcasted : 1;
    bool edge : 1;
    bool edge_global : 1;
    bool global : 1;
} tlb_ctx_t;

static void tlb_init(tlb_ctx_t *tlb, void *table) {
    memset(tlb, 0, sizeof(*tlb));
    tlb->table = table;
    tlb->asid = -1;
    tlb->current = __atomic_load_n(&kernel_pt_switched, __ATOMIC_RELAXED);
}

static void tlb_add_leaf(tlb_ctx_t *tlb, uintptr_t addr, bool global) {
    arch_pt_flush_leaf(addr, tlb->table, tlb->asid, global, tlb->current);

    if (global) {
        if (!arch_pt_flush_can_broadcast()) {
            tlb->global = true;
        } else {
            tlb->broadcasted = true;
        }
    }
}

static void tlb_add_edge(tlb_ctx_t *tlb, uintptr_t addr, bool global) {
    if (!arch_pt_flush_edge_coarse()) {
        arch_pt_flush_edge(addr, tlb->table, tlb->asid, global, tlb->current);

        if (global) {
            if (!arch_pt_flush_can_broadcast()) {
                tlb->global = true;
            } else {
                tlb->broadcasted = true;
            }
        }
    } else {
        tlb->edge = true;
        if (global) tlb->edge_global = true;
    }
}

static void tlb_remote(void *ptr) {
    tlb_ctx_t *tlb = ptr;
    arch_pt_flush(tlb->table, tlb->asid);
}

static void tlb_commit(tlb_ctx_t *tlb) {
    if (tlb->edge) {
        arch_pt_flush_edge(0, tlb->table, tlb->asid, tlb->edge_global, tlb->current);

        if (tlb->edge_global) {
            if (!arch_pt_flush_can_broadcast()) {
                tlb->global = true;
            } else {
                tlb->broadcasted = true;
            }
        }
    }

    if (tlb->broadcasted) {
        arch_pt_flush_wait();
    } else if (tlb->global) {
        smp_call_remote(NULL, tlb_remote, tlb);
    }
}

static void *early_alloc_table(unsigned level) {
    void *table = early_alloc_page();
    memset(table, 0, PAGE_SIZE);
    return table;
}

void pmap_init(void) {
    kernel_page_table = early_alloc_table(arch_pt_levels() - 1);
}

void pmap_init_switch(void) {
    arch_switch_pt_init(kernel_page_table, -1, false);
    __atomic_store_n(&kernel_pt_switched, true, __ATOMIC_RELAXED);
}

static void do_early_map(
        void *table,
        unsigned level,
        uintptr_t virt,
        uint64_t phys,
        size_t size,
        int flags,
        tlb_ctx_t *tlb
) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    do {
        if (level == 0 || (arch_pt_can_map_direct(level) && ((virt | phys) & entry_mask) == 0 && size >= entry_size)) {
            ASSERT(arch_pt_read(table, level, index) == 0);
            arch_pt_write(table, level, index, arch_pt_create_leaf(level, phys, flags, false));

            if (arch_pt_new_leaf_needs_flush()) {
                tlb_add_leaf(tlb, virt, false);
            }

            index += 1;
            virt += entry_size;
            phys += entry_size;
            size -= entry_size;
            continue;
        }

        pte_t pte = arch_pt_read(table, level, index);
        void *child;

        if (pte != 0) {
            ASSERT(arch_pt_is_edge(level, pte));
            child = arch_pt_edge_target(level, pte);
        } else {
            child = early_alloc_table(level - 1);
            arch_pt_write(table, level, index, arch_pt_create_edge(level, child));

            if (arch_pt_new_edge_needs_flush()) {
                tlb_add_edge(tlb, virt, false);
            }
        }

        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        do_early_map(child, level - 1, virt, phys, cur, flags, tlb);

        index += 1;
        virt += cur;
        phys += cur;
        size -= cur;
    } while (size != 0);
}

void pmap_early_map(uintptr_t virt, uint64_t phys, size_t size, int flags) {
    ASSERT(arch_pt_get_offset(virt | phys | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(is_kernel_address(virt));
    ASSERT(phys < phys + (size - 1));
    ASSERT(phys + (size - 1) <= cpu_max_phys_addr());

    mutex_acq(&kernel_pt_lock, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, kernel_page_table);
    do_early_map(kernel_page_table, arch_pt_levels() - 1, virt, phys, size, flags, &tlb);
    tlb_commit(&tlb);

    migrate_unlock(state);
    mutex_rel(&kernel_pt_lock);
}

static void do_early_alloc(void *table, unsigned level, uintptr_t virt, size_t size, int flags, tlb_ctx_t *tlb) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    do {
        if (level == 0) {
            ASSERT(arch_pt_read(table, level, index) == 0);
            arch_pt_write(
                    table,
                    level,
                    index,
                    arch_pt_create_leaf(level, virt_to_phys(early_alloc_page()), flags, false)
            );

            if (arch_pt_new_leaf_needs_flush()) {
                tlb_add_leaf(tlb, virt, false);
            }

            index += 1;
            virt += entry_size;
            size -= entry_size;
            continue;
        }

        pte_t pte = arch_pt_read(table, level, index);
        void *child;

        if (pte != 0) {
            ASSERT(arch_pt_is_edge(level, pte));
            child = arch_pt_edge_target(level, pte);
        } else {
            child = early_alloc_page();
            memset(child, 0, PAGE_SIZE);
            arch_pt_write(table, level, index, arch_pt_create_edge(level, child));

            if (arch_pt_new_edge_needs_flush()) {
                tlb_add_edge(tlb, virt, false);
            }
        }

        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        do_early_alloc(child, level - 1, virt, cur, flags, tlb);

        index += 1;
        virt += cur;
        size -= cur;
    } while (size != 0);
}

void pmap_early_alloc(uintptr_t virt, size_t size, int flags) {
    ASSERT(arch_pt_get_offset(virt | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(is_kernel_address(virt));

    mutex_acq(&kernel_pt_lock, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, kernel_page_table);
    do_early_alloc(kernel_page_table, arch_pt_levels() - 1, virt, size, flags, &tlb);
    tlb_commit(&tlb);

    migrate_unlock(state);
    mutex_rel(&kernel_pt_lock);
}
