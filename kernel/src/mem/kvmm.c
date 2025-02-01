#include "mem/kvmm.h"
#include "cpu/cpu.h"
#include "hydrogen/error.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/kmalloc.h"
#include "mem/pmap.h"
#include "string.h"
#include "util/panic.h"
#include "util/spinlock.h"
#include <stdbool.h>
#include <stdint.h>

// number of slots in the allocated ranges hash table
// there is no fixed cap on the number of items in the table, but increasing this improves performance
#define ALLOC_TABLE_SIZE 256
#define ALLOC_TABLE_MASK (ALLOC_TABLE_SIZE - 1)

struct vmm_range {
    uintptr_t start;
    size_t size;
    struct vmm_range *prev;
    struct vmm_range *next;
    struct vmm_range *kind_prev;
    struct vmm_range *kind_next;
    int order;
    bool free;
};

#define MIN_ORDER PAGE_SHIFT
#define MAX_ORDER 64

static struct vmm_range *ranges;
static struct vmm_range *free_ranges[MAX_ORDER - MIN_ORDER];
static uint64_t free_bitmap;
static struct vmm_range *allocations[ALLOC_TABLE_SIZE];
static spinlock_t kvmm_lock;

_Static_assert((ALLOC_TABLE_SIZE & ALLOC_TABLE_MASK) == 0, "Allocation table size must be a power of two");

// size >= 1
static int get_lower_p2(size_t size) {
    return (63 - MIN_ORDER) - __builtin_clzl(size);
}

// size >= 2
static int get_higher_p2(size_t size) {
    return (64 - MIN_ORDER) - __builtin_clzl(size - 1);
}

static void global_remove(struct vmm_range *range) {
    if (range->prev) range->prev->next = range->next;
    else ranges = range->next;
    if (range->next) range->next->prev = range->prev;
}

static void global_insert(struct vmm_range *range) {
    if (range->prev) range->prev->next = range;
    else ranges = range;
    if (range->next) range->next->prev = range;
}

static void kind_remove(struct vmm_range *range, struct vmm_range **list) {
    if (range->kind_prev) range->kind_prev->kind_next = range->kind_next;
    else *list = range->kind_next;
    if (range->kind_next) range->kind_next->kind_prev = range->kind_prev;
}

static void free_remove(struct vmm_range *range, int order) {
    kind_remove(range, &free_ranges[order]);
    if (!free_ranges[order]) free_bitmap &= ~(1ul << order);
}

static void kind_insert(struct vmm_range *range, struct vmm_range **list) {
    range->kind_prev = NULL;
    range->kind_next = *list;
    if (range->kind_next) range->kind_next->kind_prev = range;
    *list = range;
}

static void free_insert(struct vmm_range *range, int order) {
    kind_insert(range, &free_ranges[order]);
    free_bitmap |= 1ul << order;
}

static void update_order(struct vmm_range *range) {
    int new_order = get_lower_p2(range->size);

    if (new_order != range->order) {
        free_remove(range, range->order);
        free_insert(range, new_order);
        range->order = new_order;
    }
}

static bool try_merge(
        struct vmm_range *prev,
        struct vmm_range *cur,
        struct vmm_range *next,
        uintptr_t start,
        size_t size
) {
    bool prev_merge = prev != NULL && prev->free && prev->start + prev->size == start;
    bool next_merge = next != NULL && next->free && start + size == next->start;

    if (prev_merge) {
        prev->size += size;

        if (next_merge) {
            prev->size += next->size;
            prev->next = next->next;
            if (prev->next) prev->next->prev = prev;
            kfree(next, sizeof(*next));
            kfree(cur, sizeof(*cur));
        } else if (cur) {
            global_remove(cur);
        }

        update_order(prev);
        return true;
    } else if (next_merge) {
        next->start -= size;
        next->size += size;
        update_order(next);

        if (cur) {
            global_remove(cur);
        }

        return true;
    } else {
        return false;
    }
}

static hydrogen_error_t merge_or_insert(struct vmm_range *prev, struct vmm_range *next, uintptr_t start, size_t size) {
    if (!try_merge(prev, NULL, next, start, size)) {
        struct vmm_range *range = kmalloc(sizeof(*range));
        if (unlikely(!range)) return HYDROGEN_SUCCESS;
        memset(range, 0, sizeof(*range));
        range->start = start;
        range->size = size;
        range->prev = prev;
        range->next = next;
        range->order = get_lower_p2(size);
        range->free = true;

        global_insert(range);
        free_insert(range, range->order);
    }

    return HYDROGEN_SUCCESS;
}

void kvmm_add_range(uintptr_t start, size_t size) {
    ASSERT((start & PAGE_MASK) == 0);
    ASSERT((size & PAGE_MASK) == 0);
    if (size == 0) return;

    spin_lock_noirq(&kvmm_lock);

    struct vmm_range *prev = NULL;
    struct vmm_range *next = ranges;

    while (next != NULL && next->start < start) {
        prev = next;
        next = next->next;
    }

    ASSERT(prev == NULL || (prev->start + prev->size) <= start);
    ASSERT(next == NULL || start + size <= next->start);

    hydrogen_error_t error = merge_or_insert(prev, next, start, size);
    if (unlikely(error)) panic("kvmm_add_range failed (%d)", error);

    spin_unlock_noirq(&kvmm_lock);
}

static uint64_t make_hash(uint64_t x) {
    x *= 0xe9770214b82cf957;
    x ^= x >> 47;
    x *= 0x2bdd9d20d060fc9b;
    x ^= x >> 44;
    x *= 0x65c487023b406173;
    return x;
}

hydrogen_error_t kvmm_alloc(uintptr_t *out, size_t size) {
    ASSERT((size & PAGE_MASK) == 0);
    int wanted_order = get_higher_p2(size);

    spin_lock_noirq(&kvmm_lock);

    int order = __builtin_ffsl(free_bitmap >> wanted_order);
    struct vmm_range *range;

    if (unlikely(order == 0)) {
        if (wanted_order != 0 && size != (1ul << wanted_order)) {
            // The previous free list might have a range that's big enough
            order = wanted_order - 1;
            range = free_ranges[order];
            while (range != NULL && range->size < size) range = range->next;

            if (unlikely(range == NULL)) {
                spin_unlock_noirq(&kvmm_lock);
                return HYDROGEN_OUT_OF_MEMORY;
            }
        } else {
            spin_unlock_noirq(&kvmm_lock);
            return HYDROGEN_OUT_OF_MEMORY;
        }
    } else {
        order += wanted_order - 1;
        range = free_ranges[order];
    }

    struct vmm_range *alloc;

    if (range->size != size) {
        alloc = kmalloc(sizeof(*alloc));
        if (unlikely(!alloc)) {
            spin_unlock_noirq(&kvmm_lock);
            return HYDROGEN_OUT_OF_MEMORY;
        }
        memset(alloc, 0, sizeof(*alloc));
        alloc->start = range->start;
        alloc->size = size;
        alloc->prev = range->prev;
        alloc->next = range;
        alloc->free = false;
        global_insert(alloc);

        range->start += size;
        range->size -= size;
        update_order(range);
    } else {
        alloc = range;
        range->free = false;
        free_remove(range, order);
    }

    kind_insert(alloc, &allocations[make_hash(alloc->start) & ALLOC_TABLE_MASK]);

    spin_unlock_noirq(&kvmm_lock);
    *out = alloc->start;
    return HYDROGEN_SUCCESS;
}

static struct vmm_range *get_range_from_alloc(uint64_t hash, uintptr_t start, UNUSED size_t size) {
    struct vmm_range *range = allocations[hash & ALLOC_TABLE_MASK];

    for (;;) {
        ASSERT(range != NULL);
        if (range->start == start) break;
        range = range->kind_next;
    }

    ASSERT(range != NULL);
    ASSERT(range->size == size);
    ASSERT(!range->free);
    return range;
}

void kvmm_free(uintptr_t start, size_t size) {
    ASSERT((start & PAGE_MASK) == 0);
    ASSERT((size & PAGE_MASK) == 0);

    spin_lock_noirq(&kvmm_lock);

    uint64_t hash = make_hash(start);
    struct vmm_range *range = get_range_from_alloc(hash, start, size);
    kind_remove(range, &allocations[hash & ALLOC_TABLE_MASK]);

    struct vmm_range *prev = range->prev;
    struct vmm_range *next = range->next;

    if (!try_merge(prev, range, next, start, size)) {
        range->free = true;
        range->order = get_lower_p2(range->size);
        free_insert(range, range->order);
    }

    spin_unlock_noirq(&kvmm_lock);
}

hydrogen_error_t map_phys_mem(void **out, uint64_t addr, size_t size, int flags, cache_mode_t mode) {
    if (unlikely(size == 0)) return HYDROGEN_SUCCESS;

    uint64_t end = addr + (size - 1);
    if (unlikely(end < addr)) return HYDROGEN_INVALID_ARGUMENT;
    if (unlikely(end & ~cpu_features.paddr_mask)) return HYDROGEN_INVALID_ARGUMENT;

    uint64_t offset = addr & PAGE_MASK;
    addr &= ~PAGE_MASK;
    end |= PAGE_MASK;
    size = end - addr + 1;

    uintptr_t vaddr;
    hydrogen_error_t error = kvmm_alloc(&vaddr, size);
    if (unlikely(error)) return error;

    error = map_kernel_memory(vaddr, addr, size, flags, mode);
    if (unlikely(error)) return error;

    *out = (void *)(vaddr | offset);
    return HYDROGEN_SUCCESS;
}

void unmap_phys_mem(const void *ptr, size_t size) {
    if (unlikely(size == 0)) return;

    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t end = addr + (size - 1);
    addr &= ~PAGE_MASK;
    end |= PAGE_MASK;
    size = end - addr + 1;

    unmap_memory(addr, size);
    kvmm_free(addr, size);
}
