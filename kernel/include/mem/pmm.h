#pragma once

#include "kernel/pgsize.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef union page {
    struct {
        union page *next;
        size_t count;
    } free;
} page_t;

typedef struct {
    size_t total;
    size_t available;
    size_t free;
} pmm_stats_t;

extern void *hhdm_start;
extern page_t *page_array;
extern uint64_t pmm_addr_max;

void init_pmm(void);
void reclaim_loader_pages(void);

pmm_stats_t pmm_get_stats(void);

bool pmm_reserve(size_t count);
void pmm_unreserve(size_t count);

// these are guaranteed to succeed
page_t *pmm_alloc(void);
void pmm_free(page_t *page);

// returns null on failure
page_t *pmm_alloc_now(void);
void pmm_free_now(page_t *page);

static inline uint64_t page_to_phys(page_t *page) {
    return (page - page_array) << PAGE_SHIFT;
}

static inline void *page_to_virt(page_t *page) {
    return hhdm_start + ((page - page_array) << PAGE_SHIFT);
}

static inline page_t *phys_to_page(uint64_t phys) {
    return page_array + (phys >> PAGE_SHIFT);
}

static inline void *phys_to_virt(uint64_t phys) {
    return hhdm_start + phys;
}

static inline page_t *virt_to_page(const void *virt) {
    return page_array + ((virt - hhdm_start) >> PAGE_SHIFT);
}

static inline uint64_t virt_to_phys(const void *virt) {
    return virt - hhdm_start;
}
