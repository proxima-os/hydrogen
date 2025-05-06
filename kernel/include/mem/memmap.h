#pragma once

#include "arch/memmap.h"
#include "kernel/pgsize.h"
#include "util/list.h"
#include "util/shlist.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    bool is_free : 1;
    union {
        struct {
            shlist_node_t node;
            size_t count;
        } free;
        struct {
            list_node_t node;
            shlist_t objects;
            size_t num_free;
        } slab;
        struct {
            size_t references; // used as a leaf counter in page table pages
            shlist_node_t free_node;
        } anon;
    };
} __attribute__((aligned(64))) page_t;

extern uintptr_t hhdm_base;
extern uintptr_t page_array_base;
extern uint64_t kernel_base;

void memmap_init(void);

// NOTE: This must be called BEFORE any thread other than the init thread is created!
// Otherwise, race conditions could cause a UAF.
void memmap_reclaim_loader(void);

void memmap_reclaim_init(void);

void *early_alloc_page(void);

bool next_owned_ram_gap(uint64_t addr, uint64_t *head, uint64_t *tail);
bool is_area_ram(uint64_t head, uint64_t tail);

// stops iteration if the function returns false.
// returns false if iteration was stopped.
bool memmap_iter_reversed(bool (*func)(uint64_t, uint64_t, void *), void *ctx);

static inline uint64_t page_to_phys(page_t *page) {
    return (((uintptr_t)page - page_array_base) / sizeof(page_t)) << PAGE_SHIFT;
}

static inline void *page_to_virt(page_t *page) {
    return (void *)(hhdm_base + ((((uintptr_t)page - page_array_base) / sizeof(page_t)) << PAGE_SHIFT));
}

static inline void *phys_to_virt(uint64_t phys) {
    return (void *)(hhdm_base + phys);
}

static inline page_t *phys_to_page(uint64_t phys) {
    return (page_t *)(page_array_base + ((phys >> PAGE_SHIFT) * sizeof(page_t)));
}

static inline page_t *virt_to_page(void *virt) {
    return (page_t *)(page_array_base + ((((uintptr_t)virt - hhdm_base) >> PAGE_SHIFT) * sizeof(page_t)));
}

static inline uint64_t virt_to_phys(void *virt) {
    return (uintptr_t)virt - hhdm_base;
}

static inline bool is_kernel_address(uintptr_t virt) {
    return virt & (1ul << (cpu_vaddr_bits() - 1));
}

static inline uint64_t sym_to_phys(const void *sym) {
    extern const void _start;
    return kernel_base + ((uintptr_t)sym - (uintptr_t)&_start);
}
