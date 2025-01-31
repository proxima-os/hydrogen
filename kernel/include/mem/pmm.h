#pragma once

#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef HYDROGEN_DEBUG_PMM
#define HYDROGEN_DEBUG_PMM HYDROGEN_ASSERTIONS
#endif

#if HYDROGEN_DEBUG_PMM
#include "util/spinlock.h"

// this struct isn't necessary, since violating the reservation rules is a bug. however, including it in debug mode
// allows us to detect those bugs via asserts
typedef struct {
    size_t __internal_total;
    size_t __internal_free;
    spinlock_t lock;
} pmm_reservation_t;
#else
typedef struct {
} pmm_reservation_t;
#endif

typedef struct page {
    union {
        struct {
            struct page *next;
            size_t count;
        } free;
    };
#if HYDROGEN_DEBUG_PMM
    pmm_reservation_t *reservation;
#endif
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

#if HYDROGEN_DEBUG_PMM

#define PMM_RESERVE bool pmm_reserve(pmm_reservation_t *out, size_t count)
bool pmm_extend(pmm_reservation_t *reservation, size_t count);
#define PMM_UNRESERVE void pmm_unreserve(pmm_reservation_t *reservation, size_t count)
#define PMM_ALLOC page_t *pmm_alloc(pmm_reservation_t *reservation)
#define PMM_FREE void pmm_free(pmm_reservation_t *reservation, page_t *page)

#else

#define PMM_RESERVE bool pmm_reserve_impl(size_t count)
#define PMM_UNRESERVE void pmm_unreserve_impl(size_t count)
#define PMM_ALLOC page_t *pmm_alloc_impl(void)
#define PMM_FREE void pmm_free_impl(page_t *page)

#define pmm_reserve(x, count) (pmm_reserve_impl(count))
#define pmm_extend pmm_reserve
#define pmm_unreserve(x, count) (pmm_unreserve_impl(count))
#define pmm_alloc(x) (pmm_alloc_impl())
#define pmm_free(x, page) (pmm_free_impl(page))

#endif

PMM_RESERVE;
PMM_UNRESERVE;

// these are guaranteed to succeed
PMM_ALLOC;
PMM_FREE;

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
