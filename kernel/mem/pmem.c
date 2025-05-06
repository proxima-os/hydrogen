#include "mem/pmem.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/memmap.h"
#include "proc/mutex.h"
#include "sections.h"
#include "string.h"
#include "util/shlist.h"
#include <stddef.h>
#include <stdint.h>

static mutex_t pmem_lock;
static shlist_t pmem_free_list;
static pmem_stats_t pmem_stats;

pmem_stats_t pmem_get_stats(void) {
    mutex_acq(&pmem_lock, 0, false);
    pmem_stats_t stats = pmem_stats;
    mutex_rel(&pmem_lock);
    return stats;
}

bool pmem_reserve(size_t count) {
    mutex_acq(&pmem_lock, 0, false);

    bool ok = count <= pmem_stats.available;

    if (ok) {
        pmem_stats.available -= count;
        ASSERT(pmem_stats.available <= pmem_stats.free);
    }

    mutex_rel(&pmem_lock);
    return true;
}

static void do_unreserve(size_t count) {
    pmem_stats.available += count;
    ASSERT(pmem_stats.available <= pmem_stats.free);
}

void pmem_unreserve(size_t count) {
    mutex_acq(&pmem_lock, 0, false);
    do_unreserve(count);
    mutex_rel(&pmem_lock);
}

page_t *pmem_alloc(void) {
    mutex_acq(&pmem_lock, 0, false);

    page_t *page = SHLIST_HEAD(pmem_free_list, page_t, free.node);
    size_t idx = --page->free.count;
    if (likely(idx == 0)) shlist_remove_head(&pmem_free_list);
    page += idx;
    page->is_free = false;

    pmem_stats.free -= 1;
    ASSERT(pmem_stats.available <= pmem_stats.free);

    mutex_rel(&pmem_lock);
    return page;
}

void pmem_free(page_t *page) {
    page->free.count = 1;

    mutex_acq(&pmem_lock, 0, false);

    page->is_free = true;
    shlist_insert_head(&pmem_free_list, &page->free.node);

    pmem_stats.free += 1;
    ASSERT(pmem_stats.available <= pmem_stats.free);

    mutex_rel(&pmem_lock);
}

struct alloc_slow_ctx {
    page_t *page;
    uint64_t min_head;
    uint64_t max_head;
    uint64_t align_mask;
    uint64_t offset;
};

static bool alloc_slow_in_region(uint64_t head, uint64_t tail, void *ptr) {
    struct alloc_slow_ctx *ctx = ptr;

    if (tail < ctx->offset) return true;

    uint64_t alloc_head = (tail - ctx->offset) & ~ctx->align_mask;
    if (alloc_head > ctx->max_head) alloc_head = ctx->max_head;

    size_t count = (ctx->offset >> PAGE_SHIFT) + 1;

    while (head <= alloc_head) {
        if (alloc_head < ctx->min_head) return true;

        page_t *base = phys_to_page(alloc_head);
        size_t index;

        for (index = count; index > 0; index--) {
            page_t *page = &base[index - 1];

            if (!page->is_free) {
                uint64_t new_tail = page_to_phys(page) - 1;
                if (new_tail < ctx->offset) return true;
                alloc_head = (new_tail - ctx->offset) & ~ctx->align_mask;
                break;
            }
        }

        if (index != 0) continue;

        // remove the allocated pages
        page_t *amax = base + (count - 1);

        page_t *prev = NULL;
        page_t *page = SHLIST_HEAD(pmem_free_list, page_t, free.node);

        size_t num_removed = 0;

        while (page != NULL) {
            page_t *cmax = page + (page->free.count - 1);

            if (base <= cmax && amax >= page) {
                num_removed += page->free.count;

                if (amax < cmax) {
                    page_t *nmin = amax + 1;
                    nmin->free.count = cmax - amax;
                    shlist_insert_after(&pmem_free_list, &page->free.node, &nmin->free.node);
                    num_removed -= nmin->free.count;
                }

                if (page < base) {
                    page->free.count = base - page;
                    num_removed -= page->free.count;

                    if (num_removed == count) break;
                } else {
                    if (prev != NULL) {
                        shlist_remove(&pmem_free_list, &page->free.node, &prev->free.node);
                        page = SHLIST_NEXT(*prev, page_t, free.node);
                    } else {
                        shlist_remove(&pmem_free_list, &page->free.node, NULL);
                        page = SHLIST_HEAD(pmem_free_list, page_t, free.node);
                    }

                    if (num_removed == count) break;
                    continue;
                }
            }

            prev = page;
            page = SHLIST_NEXT(*page, page_t, free.node);
        }

        ASSERT(num_removed == count);

        memset(base, 0, count * sizeof(*base)); // set is_free to false for all pages
        pmem_stats.free -= count;
        ASSERT(pmem_stats.available <= pmem_stats.free);

        ctx->page = page;
        return false;
    }

    return true;
}

page_t *pmem_alloc_slow_and_unreliable(uint64_t min, uint64_t max, uint64_t align, size_t count) {
    ASSERT(count != 0);
    ASSERT(align & (align - 1));

    uint64_t align_mask = align - 1;
    if (align_mask < PAGE_MASK) align_mask = PAGE_MASK;

    uint64_t min_head = min + align_mask;
    if (min_head < min) return NULL;
    min_head &= ~align_mask;

    uint64_t max_tail = max - PAGE_MASK;
    if (max_tail > max) return NULL;
    max_tail |= PAGE_MASK;
    if (min_head > max_tail) return NULL;

    uint64_t offset = ((uint64_t)count << PAGE_SHIFT) - 1;
    if (max_tail < offset) return NULL;

    uint64_t max_head = (max_tail - offset) & ~align_mask;
    if (max_head < min_head) return NULL;

    struct alloc_slow_ctx ctx = {
            .min_head = min_head,
            .max_head = max_head,
            .align_mask = align_mask,
            .offset = offset,
    };

    mutex_acq(&pmem_lock, 0, false);
    if (pmem_stats.free >= count) memmap_iter_reversed(alloc_slow_in_region, &ctx);
    mutex_rel(&pmem_lock);
    return ctx.page;
}

static void do_free_multiple(page_t *page, size_t count) {
    memset(page, 0xff, count * sizeof(*page)); // set is_free to true for all pages
    page->free.count = count;
    shlist_insert_head(&pmem_free_list, &page->free.node);
    pmem_stats.free += count;
    ASSERT(pmem_stats.available <= pmem_stats.free);
}

void pmem_free_multiple(page_t *page, size_t count) {
    mutex_acq(&pmem_lock, 0, false);
    do_free_multiple(page, count);
    mutex_rel(&pmem_lock);
}

INIT_TEXT void pmem_add_area(uint64_t head, uint64_t tail, bool free) {
    ASSERT((head & PAGE_MASK) == 0);
    ASSERT((tail & PAGE_MASK) == PAGE_MASK);
    size_t count = ((tail - head) >> PAGE_SHIFT) + 1;

    mutex_acq(&pmem_lock, 0, false);

    pmem_stats.total += count;

    if (free) {
        do_free_multiple(phys_to_page(head), count);
        do_unreserve(count);
    }

    mutex_rel(&pmem_lock);
}
