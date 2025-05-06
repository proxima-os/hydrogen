#include "mem/kvmm.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/kmalloc.h"
#include "mem/pmap.h"
#include "proc/mutex.h"
#include "string.h"
#include "util/hash.h"
#include "util/hlist.h"
#include "util/list.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// number of slots in the allocated ranges hash table
// there is no fixed cap on the number of items in the table regardless of the number of slots,
// but increasing this improves performance of resize and free
// note: there is no real point to making this table dynamic. the only allocator kvmm can use
// is kmalloc/kfree, and that is limited to objects <=PAGE_SIZE. if we want a table larger than
// one page, we *need* to allocate it statically, and if we don't, the table is small enough
// that allocating it statically has basically no impact on total system memory usage.
#define ALLOC_TABLE_SIZE 512

typedef struct kvmm_range {
    list_node_t node;
    hlist_node_t kind_node;
    uintptr_t head;
    size_t size;
    size_t order;
    bool free : 1;
} kvmm_range_t;

static list_t kvmm_ranges;

static hlist_t kvmm_free_ranges[sizeof(size_t) * 8 - PAGE_SHIFT];
static size_t kvmm_free_bitmap;

static hlist_t kvmm_allocations[ALLOC_TABLE_SIZE];

static mutex_t kvmm_lock;

static size_t get_lower_p2(size_t size) {
    return (sizeof(long) * 8 - 1 - PAGE_SHIFT) - __builtin_clzl(size);
}

static void free_insert(kvmm_range_t *range, size_t order) {
    hlist_insert_head(&kvmm_free_ranges[order], &range->kind_node);
    kvmm_free_bitmap |= 1ul << order;
}

static void free_remove(kvmm_range_t *range, size_t order) {
    hlist_remove(&kvmm_free_ranges[order], &range->kind_node);
    if (hlist_empty(&kvmm_free_ranges[order])) kvmm_free_bitmap &= ~(1ul << order);
}

static void update_order(kvmm_range_t *range) {
    size_t order = get_lower_p2(range->size);

    if (order != range->order) {
        free_remove(range, range->order);
        free_insert(range, order);
        range->order = order;
    }
}

static size_t get_bucket(uintptr_t addr) {
    return make_hash_iptr(addr) % ALLOC_TABLE_SIZE;
}

static void alloc_insert(kvmm_range_t *range) {
    hlist_insert_head(&kvmm_allocations[get_bucket(range->head)], &range->kind_node);
}

static void alloc_remove(kvmm_range_t *range) {
    hlist_remove(&kvmm_allocations[get_bucket(range->head)], &range->kind_node);
}

static kvmm_range_t *alloc_get(uintptr_t addr) {
    kvmm_range_t *range = HLIST_HEAD(kvmm_allocations[get_bucket(addr)], kvmm_range_t, kind_node);

    for (;;) {
        ASSERT(range != NULL);
        if (range->head == addr) return range;
        range = HLIST_NEXT(*range, kvmm_range_t, kind_node);
    }
}

static bool try_merge(kvmm_range_t *prev, kvmm_range_t *next, uintptr_t head, size_t size) {
    bool prev_merge = prev != NULL && prev->free && prev->head + prev->size == head;
    bool next_merge = next != NULL && next->free && head + size == next->head;

    if (prev_merge) {
        prev->size += size;

        if (next_merge) {
            prev->size += next->size;
            list_remove(&kvmm_ranges, &next->node);
            free_remove(next, next->order);
            kfree(next, sizeof(*next));
        }

        update_order(prev);
        return true;
    } else if (next_merge) {
        next->head -= size;
        next->size += size;
        update_order(next);

        return true;
    } else {
        return false;
    }
}

static bool merge_or_insert(kvmm_range_t *prev, kvmm_range_t *next, uintptr_t head, size_t size) {
    if (!try_merge(prev, next, head, size)) {
        kvmm_range_t *range = kmalloc(sizeof(*range));
        if (unlikely(!range)) return false;
        memset(range, 0, sizeof(*range));
        range->head = head;
        range->size = size;
        range->order = get_lower_p2(size);
        range->free = true;

        list_insert_after(&kvmm_ranges, &prev->node, &range->node);
        free_insert(range, range->order);
    }

    return true;
}

void kvmm_add_range(uintptr_t head, uintptr_t tail) {
    uintptr_t aligned_head = (head + PAGE_MASK) & ~PAGE_MASK;
    if (aligned_head < head) return;

    uintptr_t aligned_tail = (tail - PAGE_MASK) | PAGE_MASK;
    if (aligned_tail > tail) return;
    if (aligned_head >= aligned_tail) return;

    size_t size = aligned_tail - aligned_head + 1;

    mutex_acq(&kvmm_lock, 0, false);

    kvmm_range_t *prev = NULL;
    kvmm_range_t *next = HLIST_HEAD(kvmm_ranges, kvmm_range_t, node);

    while (next != NULL && next->head < head) {
        prev = next;
        next = HLIST_NEXT(*next, kvmm_range_t, node);
    }

    ASSERT(prev == NULL || (prev->head + prev->size) <= head);
    ASSERT(next == NULL || (head + size) <= next->head);

    merge_or_insert(prev, next, head, size);
    mutex_rel(&kvmm_lock);
}

static bool is_power_of_two(size_t size) {
    return (size & (size - 1)) == 0;
}

static kvmm_range_t *select_range(size_t size) {
    // the minimum order that *can* contain a range that's large enough.
    // unless the size is exactly a power of two, this order can still
    // contain ranges that are too small - for a guaranteed fit, go one order higher.
    size_t min_order = get_lower_p2(size);
    size_t bitmap = kvmm_free_bitmap >> min_order;
    if (unlikely(!bitmap)) return NULL;

    size_t guarantee_offset = is_power_of_two(size) ? 0 : 1;
    size_t guarantee_bitmap = bitmap >> guarantee_offset;

    if (likely(guarantee_bitmap != 0)) {
        size_t order = min_order + guarantee_offset + __builtin_ctzl(guarantee_bitmap);
        kvmm_range_t *range = HLIST_HEAD(kvmm_free_ranges[order], kvmm_range_t, kind_node);
        ASSERT(range->free);
        return range;
    }

    // we can't get it from an order where a fit is guaranteed, search the min_order list
    kvmm_range_t *range = HLIST_HEAD(kvmm_free_ranges[min_order], kvmm_range_t, kind_node);

    for (;;) {
        if (range == NULL) return NULL;
        ASSERT(range->free);
        if (range->size >= size) return range;
        range = HLIST_NEXT(*range, kvmm_range_t, kind_node);
    }
}

uintptr_t kvmm_alloc(size_t size) {
    ASSERT((size & PAGE_MASK) == 0);
    ASSERT(size != 0);

    mutex_acq(&kvmm_lock, 0, false);

    kvmm_range_t *src_range = select_range(size);
    if (unlikely(!src_range)) {
        mutex_rel(&kvmm_lock);
        return 0;
    }

    ASSERT(src_range->size >= size);
    ASSERT(src_range->free);

    kvmm_range_t *range;

    if (src_range->size > size) {
        range = kmalloc(sizeof(*range));
        if (unlikely(!range)) {
            mutex_rel(&kvmm_lock);
            return 0;
        }

        memset(range, 0, sizeof(*range));
        range->head = src_range->head;
        range->size = size;
        range->free = false;
        list_insert_before(&kvmm_ranges, &src_range->node, &range->node);

        src_range->head += size;
        src_range->size -= size;
        update_order(src_range);
    } else {
        range = src_range;
        free_remove(range, range->order);
        range->free = false;
    }

    alloc_insert(range);

    uintptr_t addr = range->head;
    mutex_rel(&kvmm_lock);
    return addr;
}

bool kvmm_resize(uintptr_t address, size_t old_size, size_t new_size, bool resize_mapping) {
    ASSERT((new_size & PAGE_MASK) == 0);
    ASSERT(new_size != 0);

    if (unlikely(old_size == new_size)) return true;

    mutex_acq(&kvmm_lock, 0, false);

    kvmm_range_t *range = alloc_get(address);
    ASSERT(range->size == old_size);

    kvmm_range_t *next = HLIST_NEXT(*range, kvmm_range_t, node);

    if (old_size > new_size) {
        bool ok = merge_or_insert(range, next, range->head + new_size, old_size - new_size);

        if (likely(ok)) {
            range->size = new_size;
            if (resize_mapping) pmap_unmap(NULL, range->head + new_size, old_size - new_size);
        }

        mutex_rel(&kvmm_lock);
        return ok;
    }

    size_t extra = new_size - old_size;
    bool ok = next != NULL && next->free && range->head + old_size == next->head && next->size >= extra;

    if (resize_mapping && likely(ok)) {
        ok = pmap_prepare(NULL, range->head + old_size, extra);
    }

    if (likely(ok)) {
        range->size += extra;
        next->head += extra;
        next->size -= extra;
        update_order(next);
    }

    mutex_rel(&kvmm_lock);
    return ok;
}

void kvmm_free(uintptr_t address, size_t size) {
    mutex_acq(&kvmm_lock, 0, false);

    kvmm_range_t *range = alloc_get(address);
    ASSERT(range->size == size);
    alloc_remove(range);

    if (try_merge(
                HLIST_PREV(*range, kvmm_range_t, node),
                HLIST_NEXT(*range, kvmm_range_t, node),
                range->head,
                range->size
        )) {
        list_remove(&kvmm_ranges, &range->node);
        kfree(range, sizeof(*range));
    } else {
        range->free = true;
        range->order = get_lower_p2(size);
        free_insert(range, range->order);
    }

    mutex_rel(&kvmm_lock);
}
