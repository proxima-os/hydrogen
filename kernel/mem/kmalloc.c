#include "mem/kmalloc.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/memmap.h"
#include "mem/pmem.h"
#include "proc/mutex.h"
#include "string.h"
#include "util/list.h"
#include "util/shlist.h"
#include <stddef.h>

struct free_obj {
    shlist_node_t node;
};

#define MIN_ALLOC_SIZE (sizeof(struct free_obj))
#define ZERO_PTR ((void *)_Alignof(max_align_t))

static list_t buckets[PAGE_SHIFT];
static mutex_t bucket_locks[PAGE_SHIFT];

static inline unsigned get_bucket(size_t size) {
    return (8 * sizeof(long)) - __builtin_clzl(size - 1);
}

static inline size_t get_bucket_size(unsigned bucket) {
    return 1ul << bucket;
}

static inline size_t get_bucket_max(unsigned bucket) {
    return PAGE_SIZE >> bucket;
}

static inline struct free_obj *get_free_obj(unsigned bucket) {
    page_t *page = LIST_HEAD(buckets[bucket], page_t, slab.node);
    if (unlikely(!page)) return NULL;

    struct free_obj *obj = SHLIST_REMOVE_HEAD(page->slab.objects, struct free_obj, node);

    if (unlikely(shlist_empty(&page->slab.objects))) {
        list_remove(&buckets[bucket], &page->slab.node);
    }

    return obj;
}

static inline void put_free_obj(page_t *page, struct free_obj *obj, unsigned bucket) {
    shlist_insert_head(&page->slab.objects, &obj->node);
    size_t ncount = ++page->slab.num_free;

    if (ncount == 1) {
        list_insert_head(&buckets[bucket], &page->slab.node);
    } else if (ncount == get_bucket_max(bucket)) {
        ASSERT(ncount != 1);
        list_remove(&buckets[bucket], &page->slab.node);
        pmem_free_now(page);
    }
}

void *kmalloc(size_t size) {
    ASSERT(size <= PAGE_SIZE);

    if (unlikely(size == 0)) {
        return ZERO_PTR;
    }

    if (unlikely(size == PAGE_SIZE)) {
        page_t *page = pmem_alloc_now();
        if (unlikely(!page)) return NULL;
        return page_to_virt(page);
    }

    if (size < MIN_ALLOC_SIZE) size = MIN_ALLOC_SIZE;

    unsigned bucket = get_bucket(size);
    mutex_acq(&bucket_locks[bucket], false);

    struct free_obj *obj = get_free_obj(bucket);

    if (unlikely(!obj)) {
        mutex_rel(&bucket_locks[bucket]);

        page_t *page = pmem_alloc_now();
        if (unlikely(!page)) return NULL;

        obj = page_to_virt(page);

        shlist_clear(&page->slab.objects);
        page->slab.num_free = 0;

        size = get_bucket_size(bucket);

        for (size_t offset = size; offset < PAGE_SIZE; offset += size) {
            struct free_obj *cur = (void *)obj + offset;
            shlist_insert_head(&page->slab.objects, &cur->node);
            page->slab.num_free += 1;
        }

        mutex_acq(&bucket_locks[bucket], false);
        list_insert_head(&buckets[bucket], &page->slab.node);
    }

    mutex_rel(&bucket_locks[bucket]);
    return obj;
}

void *krealloc(void *ptr, size_t old_size, size_t new_size) {
    ASSERT(new_size <= PAGE_SIZE);

    if (unlikely(!ptr)) return kmalloc(new_size);
    if (unlikely(old_size == 0)) return kmalloc(new_size);
    if (unlikely(new_size == 0)) {
        kfree(ptr, old_size);
        return ZERO_PTR;
    }

    if (old_size < MIN_ALLOC_SIZE) old_size = MIN_ALLOC_SIZE;
    if (new_size < MIN_ALLOC_SIZE) new_size = MIN_ALLOC_SIZE;

    unsigned old_bucket = get_bucket(old_size);
    unsigned new_bucket = get_bucket(new_size);

    if (old_bucket == new_bucket) return ptr;

    void *ptr2 = kmalloc(new_size);
    if (unlikely(!ptr2)) return NULL;
    memcpy(ptr2, ptr, old_size < new_size ? old_size : new_size);
    kfree(ptr, old_size);
    return ptr2;
}

void kfree(void *ptr, size_t size) {
    if (unlikely(!ptr)) return;
    if (unlikely(size == 0)) return;

    page_t *page = virt_to_page(ptr);

    if (unlikely(size == PAGE_SIZE)) {
        pmem_free_now(page);
        return;
    }

    struct free_obj *obj = ptr;
    unsigned bucket = get_bucket(size);

    mutex_acq(&bucket_locks[bucket], false);
    put_free_obj(page, obj, bucket);
    mutex_rel(&bucket_locks[bucket]);
}
