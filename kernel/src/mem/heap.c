#include "mem/heap.h"
#include "asm/irq.h"
#include "compiler.h"
#include "cpu/cpu.h"
#include "mem/pmm.h"
#include "sched/mutex.h"
#include "sched/sched.h"
#include "string.h"
#include "util/list.h"
#include <stddef.h>

#define ZERO_PTR ((void *)_Alignof(max_align_t))
#define MIN_ALLOC_SIZE 16

_Static_assert(MIN_ALLOC_SIZE >= sizeof(list_node_t), "MIN_ALLOC_SIZE too small");

struct free_obj {
    struct free_obj *next;
};

static struct free_obj *objects[PAGE_SHIFT + 1];
static mutex_t heap_lock[PAGE_SHIFT + 1];

static int size_to_order(size_t size) {
    if (size < MIN_ALLOC_SIZE) size = MIN_ALLOC_SIZE;
    return 64 - __builtin_clzl(size - 1);
}

static void *do_alloc(int order) {
    mutex_lock(&heap_lock[order]);

    struct free_obj *obj = objects[order];

    if (unlikely(!obj)) {
        mutex_unlock(&heap_lock[order]);

        page_t *page = alloc_page_now();
        if (unlikely(!page)) return NULL;
        obj = page_to_virt(page);

        if (likely(order != PAGE_SHIFT)) {
            struct free_obj *objs = obj;
            struct free_obj *last = obj;
            size_t size = 1ul << order;

            for (size_t i = size; i < PAGE_SIZE; i += size) {
                struct free_obj *obj = (void *)objs + i;
                last->next = obj;
                last = obj;
            }

            mutex_lock(&heap_lock[order]);
            last->next = objects[order];
            objects[order] = objs->next;
            mutex_unlock(&heap_lock[order]);
        }
    } else {
        objects[order] = obj->next;
        mutex_unlock(&heap_lock[order]);
    }

    return obj;
}

#define MAGAZINE_SIZE 31

struct magazine {
    void *ptrs[MAGAZINE_SIZE];
    struct magazine *next;
};

static void cache_swap(__seg_gs heap_cache_t *cache) {
    magazine_t *c = cache->cur;
    int cc = cache->count;
    cache->cur = cache->prev;
    cache->count = cache->prev_count;
    cache->prev = c;
    cache->prev_count = cc;
}

typedef struct {
    magazine_t *full;
    magazine_t *empty;
    mutex_t lock;
} depot_t;

static depot_t depots[PAGE_SHIFT + 1];

typedef __seg_gs heap_cache_t heap_cache_local_t;

static void *alloc_order(int order) {
    if (unlikely(order > PAGE_SHIFT)) {
        return NULL;
    }

    heap_cache_local_t *cache = &current_cpu.caches[order];

    disable_preempt();

    if (likely(cache->count)) {
        void *ptr = cache->cur->ptrs[--cache->count];
        enable_preempt();
        return ptr;
    }

    if (likely(cache->prev_count)) {
        cache_swap(cache);
        void *ptr = cache->cur->ptrs[--cache->count];
        enable_preempt();
        return ptr;
    }

    irq_state_t state = save_disable_irq();
    enable_preempt();

    depot_t *depot = &depots[order];
    mutex_lock(&depot->lock);

    if (likely(depot->full)) {
        if (likely(cache->prev)) {
            cache->prev->next = depot->empty;
            depot->empty = cache->prev;
        }

        cache->prev = cache->cur;
        cache->prev_count = cache->count;

        cache->cur = depot->full;
        depot->full = cache->cur->next;

        cache->count = MAGAZINE_SIZE;
        void *ptr = cache->cur->ptrs[--cache->count];

        mutex_unlock(&depot->lock);
        restore_irq(state);
        return ptr;
    }

    mutex_unlock(&depot->lock);
    restore_irq(state);

    return do_alloc(order);
}

void *kalloc(size_t size) {
    if (unlikely(size == 0)) return ZERO_PTR;
    return alloc_order(size_to_order(size));
}

void *krealloc(void *ptr, size_t orig_size, size_t size) {
    if (unlikely(ptr == NULL || ptr == ZERO_PTR)) return kalloc(size);
    if (unlikely(size == 0)) {
        kfree(ptr, orig_size);
        return ZERO_PTR;
    }

    int order = size_to_order(size);
    int orig_order = size_to_order(orig_size);
    if (order == orig_order) return ptr;

    size_t copy_size = orig_order < order ? (1ul << orig_order) : size;

    void *ptr2 = alloc_order(order);
    if (unlikely(!ptr2)) return NULL;
    memcpy(ptr2, ptr, copy_size);
    kfree(ptr, orig_size);
    return ptr2;
}

void kfree(void *ptr, size_t size) {
    if (unlikely(ptr == NULL || ptr == ZERO_PTR)) return;

    int order = size_to_order(size);

    heap_cache_local_t *cache = &current_cpu.caches[order];

    disable_preempt();

    if (likely(cache->cur) && likely(cache->count < MAGAZINE_SIZE)) {
        cache->cur->ptrs[cache->count++] = ptr;
        enable_preempt();
        return;
    }

    if (likely(cache->prev) && likely(cache->prev_count == 0)) {
        cache_swap(cache);
        cache->cur->ptrs[cache->count++] = ptr;
        enable_preempt();
        return;
    }

    irq_state_t state = save_disable_irq();
    enable_preempt();

    depot_t *depot = &depots[order];
    mutex_lock(&depot->lock);

    if (likely(depot->empty)) {
        if (likely(cache->prev)) {
            cache->prev->next = depot->full;
            depot->full = cache->prev;
        }

        cache->prev = cache->cur;
        cache->prev_count = cache->count;

        cache->cur = depot->empty;
        depot->empty = cache->cur->next;

        cache->count = 0;
        cache->cur->ptrs[cache->count++] = ptr;

        mutex_unlock(&depot->lock);
        restore_irq(state);
        return;
    }

    magazine_t *mag = do_alloc(size_to_order(sizeof(magazine_t)));

    if (likely(mag)) {
        if (likely(cache->prev)) {
            cache->prev->next = depot->full;
            depot->full = cache->prev;
        }

        cache->prev = cache->cur;
        cache->prev_count = cache->count;

        cache->cur = mag;
        cache->count = 1;
        cache->cur->ptrs[0] = ptr;

        mutex_unlock(&depot->lock);
        restore_irq(state);
        return;
    }

    mutex_unlock(&depot->lock);
    restore_irq(state);

    struct free_obj *obj = ptr;
    mutex_lock(&heap_lock[order]);
    obj->next = objects[order];
    objects[order] = obj;
    mutex_unlock(&heap_lock[order]);
}
