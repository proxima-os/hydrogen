#include "mem/kmalloc.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/pmm.h"
#include "string.h"
#include "util/spinlock.h"
#include <stddef.h>

#define ZERO_PTR ((void *)_Alignof(max_align_t))

#define ORDER(x) (64 - __builtin_clzl((x) - 1))
#define MIN_ORDER (ORDER(_Alignof(max_align_t)))
#define MIN_SIZE (1ul << MIN_ORDER)
#define NUM_ORDERS ((PAGE_SHIFT - MIN_ORDER) + 1)

struct free_obj {
    struct free_obj *next;
};

static struct free_obj *objects[NUM_ORDERS];
static spinlock_t locks[NUM_ORDERS];

void *kmalloc(size_t size) {
    if (unlikely(size == 0)) return ZERO_PTR;
    if (size < MIN_SIZE) size = MIN_SIZE;

    int order = ORDER(size);
    if (unlikely(order > PAGE_SHIFT)) return NULL;

    spin_lock_noirq(&locks[order - MIN_ORDER]);
    struct free_obj *obj = objects[order - MIN_ORDER];
    if (likely(obj)) objects[order - MIN_ORDER] = obj->next;
    spin_unlock_noirq(&locks[order - MIN_ORDER]);

    if (unlikely(!obj)) {
        page_t *page = pmm_alloc_now();
        if (unlikely(!page)) return NULL;

        obj = page_to_virt(page);

        if (order != PAGE_SHIFT) {
            struct free_obj *last = obj;
            size = 1ul << order;

            for (size_t i = size; i < PAGE_SIZE; i += size) {
                struct free_obj *cur = (void *)obj + i;
                last->next = cur;
                last = cur;
            }

            spin_lock_noirq(&locks[order - MIN_ORDER]);
            last->next = objects[order - MIN_ORDER];
            objects[order - MIN_ORDER] = obj->next;
            spin_unlock_noirq(&locks[order - MIN_ORDER]);
        }
    }

    return obj;
}

void *krealloc(void *ptr, size_t old_size, size_t new_size) {
    if (unlikely(ptr == NULL) || unlikely(old_size == 0)) return kmalloc(new_size);
    if (unlikely(new_size == 0)) {
        kfree(ptr, old_size);
        return ZERO_PTR;
    }

    int old_order = ORDER(old_size);
    int new_order = ORDER(new_size);
    if (unlikely(old_order == new_order)) return ptr;

    void *ptr2 = kmalloc(new_size);
    if (unlikely(!ptr2)) return NULL;
    memcpy(ptr2, ptr, old_size < new_size ? old_size : new_size);
    kfree(ptr, old_size);
    return ptr2;
}

void kfree(void *ptr, size_t size) {
    if (unlikely(ptr == NULL) || unlikely(size == 0)) return;

    struct free_obj *obj = ptr;
    int order = ORDER(size) - MIN_ORDER;

    spin_lock_noirq(&locks[order - MIN_ORDER]);
    obj->next = objects[order - MIN_ORDER];
    objects[order - MIN_ORDER] = obj;
    spin_unlock_noirq(&locks[order - MIN_ORDER]);
}
