#include "mem/pmap.h"
#include "arch/pmap.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/memmap.h"
#include "proc/mutex.h"
#include "string.h"
#include <stddef.h>
#include <stdint.h>

static void *kernel_page_table;
static mutex_t kernel_pt_lock;

static void *early_alloc_table(unsigned level) {
    void *table = early_alloc_page();
    memset(table, 0, PAGE_SIZE);
    return table;
}

void pmap_init(void) {
    kernel_page_table = early_alloc_table(arch_pt_levels() - 1);
}

void pmap_init_switch(void) {
    arch_switch_pt_init(kernel_page_table);
}

static void do_early_map(void *table, unsigned level, uintptr_t virt, uint64_t phys, size_t size, int flags) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    do {
        if (level == 0 || (arch_pt_can_map_direct(level) && ((virt | phys) & entry_mask) == 0 && size >= entry_size)) {
            ASSERT(arch_pt_read(table, level, index) == 0);
            arch_pt_write(table, level, index, arch_pt_create_leaf(level, phys, flags, false));
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
        }

        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        do_early_map(child, level - 1, virt, phys, cur, flags);

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

    mutex_acq(&kernel_pt_lock, false);
    do_early_map(kernel_page_table, arch_pt_levels() - 1, virt, phys, size, flags);
    mutex_rel(&kernel_pt_lock);
}

static void do_early_alloc(void *table, unsigned level, uintptr_t virt, size_t size, int flags) {
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
        }

        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        do_early_alloc(child, level - 1, virt, cur, flags);

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
    do_early_alloc(kernel_page_table, arch_pt_levels() - 1, virt, size, flags);
    mutex_rel(&kernel_pt_lock);
}
