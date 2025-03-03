#include "mem/kmalloc.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/pmm.h"
#include "string.h"
#include "thread/mutex.h"
#include <stddef.h>

#define ZERO_PTR ((void *)_Alignof(max_align_t))

#define ORDER(x) (64 - __builtin_clzl((x) - 1))
#define MIN_ORDER (ORDER(_Alignof(max_align_t)))
#define MIN_SIZE (1ul << MIN_ORDER)
#define NUM_ORDERS (PAGE_SHIFT - MIN_ORDER)

struct slab_obj {
    struct slab_obj *next;
};

static page_t *slabs[NUM_ORDERS];
static mutex_t locks[NUM_ORDERS];

void *kmalloc(size_t size) {
    if (unlikely(size == 0)) return ZERO_PTR;

    if (size < MIN_SIZE) size = MIN_SIZE;

    int order = ORDER(size);
    if (unlikely(order > PAGE_SHIFT)) return NULL;
    if (unlikely(order == PAGE_SHIFT)) return page_to_virt(pmm_alloc(false));

    mutex_lock(&locks[order - MIN_ORDER]);

    page_t *slab = slabs[order - MIN_ORDER];
    struct slab_obj *obj;

    if (likely(slab)) {
        obj = slab->slab.objs;
        slab->slab.objs = obj->next;

        if (unlikely(--slab->slab.nfree == 0)) {
            slabs[order - MIN_ORDER] = slab->slab.next;

            if (slab->slab.next) slab->slab.next->slab.prev = NULL;
        }
    } else {
        slab = pmm_alloc(false);
        obj = page_to_virt(slab);

        struct slab_obj *last = obj;

        for (size_t offset = 1ul << order; offset < PAGE_SIZE; offset += 1ul << order) {
            struct slab_obj *cur = (void *)obj + offset;
            last->next = cur;
            last = cur;
        }

        last->next = NULL;

        slab->slab.prev = NULL;
        slab->slab.next = NULL;
        slab->slab.objs = obj->next;
        slab->slab.nfree = (PAGE_SIZE >> order) - 1;

        slabs[order - MIN_ORDER] = slab;
    }

    mutex_unlock(&locks[order - MIN_ORDER]);
    return obj;
}

void kfree(void *ptr, size_t size) {
    if (unlikely(ptr == NULL) || unlikely(size == 0)) return;

    page_t *slab = virt_to_page(ptr);
    struct slab_obj *obj = ptr;
    int order = ORDER(size);

    if (unlikely(order == PAGE_SHIFT)) {
        pmm_free(slab, false);
        return;
    }

    mutex_lock(&locks[order - MIN_ORDER]);

    obj->next = slab->slab.objs;
    slab->slab.objs = obj;

    if (unlikely(slab->slab.nfree++ == 0)) {
        slab->slab.prev = NULL;
        slab->slab.next = slabs[order - MIN_ORDER];

        slabs[order - MIN_ORDER] = slab;

        if (slab->slab.next) slab->slab.next->slab.prev = slab;
    } else if (unlikely(slab->slab.nfree == (PAGE_SIZE >> order))) {
        if (slab->slab.prev) slab->slab.prev->slab.next = slab->slab.next;
        else slabs[order - MIN_ORDER] = slab->slab.next;

        if (slab->slab.next) slab->slab.next->slab.prev = slab->slab.prev;

        pmm_free(slab, false);
    }

    mutex_unlock(&locks[order - MIN_ORDER]);
}
