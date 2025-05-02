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

void pmem_add_area(uint64_t head, uint64_t tail, bool free);
