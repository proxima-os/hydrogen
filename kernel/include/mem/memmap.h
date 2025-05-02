#pragma once

#include "kernel/pgsize.h"
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
    };
} __attribute__((aligned(64))) page_t;

extern uintptr_t hhdm_base;
extern uintptr_t page_array_base;

void memmap_init(void);

// NOTE: This must be called BEFORE any thread other than the init thread is created!
// Otherwise, race conditions could cause a UAF.
void memmap_reclaim_loader(void);

void *early_alloc_page(void);

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

