#include "mem/pmem.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/memmap.h"
#include "proc/mutex.h"
#include "string.h"
#include "util/shlist.h"

static mutex_t pmem_lock;
static shlist_t pmem_free_list;
static pmem_stats_t pmem_stats;

pmem_stats_t pmem_get_stats(void) {
    mutex_acq(&pmem_lock, false);
    pmem_stats_t stats = pmem_stats;
    mutex_rel(&pmem_lock);
    return stats;
}

bool pmem_reserve(size_t count) {
    mutex_acq(&pmem_lock, false);

    bool ok = count <= pmem_stats.available;

    if (ok) {
        pmem_stats.available -= count;
        ASSERT(pmem_stats.available <= pmem_stats.free);
    }

    mutex_rel(&pmem_lock);
    return true;
}

void pmem_unreserve(size_t count) {
    mutex_acq(&pmem_lock, false);

    pmem_stats.available += count;
    ASSERT(pmem_stats.available <= pmem_stats.free);

    mutex_rel(&pmem_lock);
}

page_t *pmem_alloc(void) {
    mutex_acq(&pmem_lock, false);

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

    mutex_acq(&pmem_lock, false);

    shlist_insert_head(&pmem_free_list, &page->free.node);

    pmem_stats.free += 1;
    ASSERT(pmem_stats.available <= pmem_stats.free);

    mutex_rel(&pmem_lock);
}

void pmem_add_area(uint64_t head, uint64_t tail, bool free) {
    size_t count = ((tail - head) >> PAGE_SHIFT) + 1;

    mutex_acq(&pmem_lock, false);

    pmem_stats.total += count;

    if (free) {
        page_t *page = phys_to_page(head);
        memset(page, 0xff, count * sizeof(*page)); // set is_free to 1 for all pages in the region
        page->free.count = count;
        shlist_insert_head(&pmem_free_list, &page->free.node);
        pmem_stats.available += count;
        pmem_stats.free += count;
    }

    mutex_rel(&pmem_lock);
}
