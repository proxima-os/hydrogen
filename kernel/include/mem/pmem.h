#pragma once

#include "kernel/compiler.h"
#include "mem/memmap.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t total;
    size_t available;
    size_t free;
} pmem_stats_t;

pmem_stats_t pmem_get_stats(void);

bool pmem_reserve(size_t count);
void pmem_unreserve(size_t count);

page_t *pmem_alloc(void);
void pmem_free(page_t *page);

static inline page_t *pmem_alloc_now(void) {
    if (unlikely(!pmem_reserve(1))) return NULL;
    return pmem_alloc();
}

static inline void pmem_free_now(page_t *page) {
    pmem_free(page);
    pmem_unreserve(1);
}

// internal
void pmem_acquire(void);
void pmem_add_area(uint64_t head, uint64_t tail, bool free);
void pmem_release(void);

// all parameters except count are in bytes. count is in pages.
page_t *pmem_alloc_slow_and_unreliable(uint64_t min, uint64_t max, uint64_t align, size_t count);
void pmem_free_multiple(page_t *page, size_t count);

static inline page_t *pmem_alloc_slow_and_unreliable_now(uint64_t min, uint64_t max, uint64_t align, size_t count) {
    if (unlikely(!pmem_reserve(count))) return NULL;
    page_t *page = pmem_alloc_slow_and_unreliable(min, max, align, count);
    if (unlikely(page == NULL)) pmem_unreserve(count);
    return page;
}

static inline void pmem_free_multiple_now(page_t *page, size_t count) {
    pmem_free_multiple(page, count);
    pmem_unreserve(count);
}
