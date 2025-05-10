#include "mem/object/anonymous.h"
#include "errno.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/memmap.h"
#include "mem/pmem.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/mutex.h"
#include "string.h"
#include "util/object.h"

#if __SIZEOF_POINTER__ == 8
#define POINTER_SHIFT 3
#elif __SIZEOF_POINTER__ == 4
#define POINTER_SHIFT 2
#else
#error "Unsupported pointer size"
#endif

#define LEVEL_SHIFT (PAGE_SHIFT - POINTER_SHIFT)
#define LEVEL_COUNT (1ul << LEVEL_SHIFT)
#define LEVEL_MASK (LEVEL_COUNT - 1)

typedef struct {
    mem_object_t base;
    void *root;
    size_t levels;
    size_t count;
    size_t tables;
    mutex_t update_lock;
} anon_mem_object_t;

static void free_entry(void *ptr, size_t level, size_t count, bool is_last_in_level) {
    if (level == 0) {
        pmem_free(ptr);
        return;
    }

    size_t max;

    if (!is_last_in_level) {
        max = LEVEL_COUNT - 1;
    } else {
        max = ((count - 1) >> ((level - 1) * LEVEL_SHIFT)) & LEVEL_MASK;
    }

    void **table = ptr;

    for (size_t i = 0; i <= max; i++) {
        ptr = table[i];
        if (ptr != NULL) free_entry(ptr, level - 1, count, i == max);
    }

    pmem_free(virt_to_page(table));
}

static void anon_mem_object_free(object_t *ptr) {
    anon_mem_object_t *self = (anon_mem_object_t *)ptr;
    free_entry(self->root, self->levels, self->count, true);
    pmem_unreserve(self->count);
    pmem_unreserve(self->tables);
    vfree(self, sizeof(*self));
}

static hydrogen_ret_t anon_mem_object_get_page(mem_object_t *ptr, uint64_t index) {
    anon_mem_object_t *self = (anon_mem_object_t *)ptr;
    if (unlikely(index >= self->count)) return ret_error(ENXIO);

    void **curptr = &self->root;

    for (size_t i = self->levels; i > 0; i--) {
        void **table = __atomic_load_n(curptr, __ATOMIC_ACQUIRE);

        if (table == NULL) {
            mutex_acq(&self->update_lock, 0, false);
            table = *curptr;

            if (table == NULL) {
                table = page_to_virt(pmem_alloc());
                memset(table, 0, PAGE_SIZE);
                __atomic_store_n(curptr, table, __ATOMIC_RELEASE);
            }

            mutex_rel(&self->update_lock);
        }

        curptr = &table[(index >> ((i - 1) * LEVEL_SHIFT)) & LEVEL_MASK];
    }

    page_t *page = __atomic_load_n(curptr, __ATOMIC_ACQUIRE);

    if (unlikely(!page)) {
        mutex_acq(&self->update_lock, 0, false);
        page = *curptr;

        if (page == NULL) {
            page = pmem_alloc();
            memset(page_to_virt(page), 0, PAGE_SIZE);
            __atomic_store_n(curptr, page, __ATOMIC_RELEASE);
        }

        mutex_rel(&self->update_lock);
    }

    return ret_pointer(page);
}

static const mem_object_ops_t ops = {
        .base.free = anon_mem_object_free,
        .get_page = anon_mem_object_get_page,
};

static size_t count_to_levels(size_t count) {
    if (count < 2) return 0;

    unsigned bits = 64 - __builtin_clzll(count - 1);
    return (bits + (LEVEL_SHIFT - 1)) / LEVEL_SHIFT;
}

int anon_mem_object_create(mem_object_t **out, size_t pages) {
    size_t levels = count_to_levels(pages);
    size_t tables = 0;
    size_t sub_full_tables = 0;

    for (size_t i = levels; i > 0; i--) {
        size_t index = ((pages - 1) >> ((i - 1) * LEVEL_SHIFT)) & LEVEL_MASK;
        ASSERT(i != levels || index >= 1);

        tables += sub_full_tables + 1;
        sub_full_tables *= LEVEL_COUNT;
        sub_full_tables += index;
    }

    size_t nreserve = tables + pages;
    if (nreserve != 0 && unlikely(!pmem_reserve(nreserve))) return ENOMEM;

    anon_mem_object_t *object = vmalloc(sizeof(*object));
    if (unlikely(!object)) {
        if (nreserve != 0) pmem_unreserve(nreserve);
        return ENOMEM;
    }
    memset(object, 0, sizeof(*object));

    object->base.base.ops = &ops.base;
    mem_object_init(&object->base);
    object->levels = levels;
    object->count = pages;
    object->tables = tables;

    *out = &object->base;
    return 0;
}
