#include "mem/object/anonymous.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "kernel/return.h"
#include "mem/memmap.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/mutex.h"
#include "proc/rcu.h"
#include "string.h"
#include "util/list.h"
#include "util/object.h"
#include "util/shlist.h"
#include <hydrogen/types.h>
#include <stdint.h>

#if __SIZEOF_POINTER__ == 8
#define POINTER_SHIFT 3
#elif __SIZEOF_POINTER__ == 4
#define POINTER_SHIFT 2
#else
#error "Unsupported pointer size"
#endif

_Static_assert(PAGE_SIZE >= 64, "PAGE_SIZE too small");

#define LEVEL_SHIFT (PAGE_SHIFT - POINTER_SHIFT)
#define LEVEL_COUNT (1ul << LEVEL_SHIFT)
#define LEVEL_MASK (LEVEL_COUNT - 1)

static size_t level_index(size_t index, size_t level) {
    return (index >> (level * LEVEL_SHIFT)) & LEVEL_MASK;
}

static void free_entry(void *ptr, size_t level, size_t count, bool is_last) {
    if (!ptr) return;

    if (level != 0) {
        size_t max;

        if (!is_last) {
            max = LEVEL_COUNT - 1;
        } else {
            max = level_index(count - 1, level - 1);
        }

        void **table = ptr;

        for (size_t i = 0; i <= max; i++) {
            free_entry(table[i], level - 1, count, is_last && i == max);
        }
    }

    pmem_free(virt_to_page(ptr));
}

static void anon_mem_object_free(object_t *ptr) {
    anon_mem_object_t *self = (anon_mem_object_t *)ptr;
    free_entry((void *)(self->root & ~PAGE_MASK), self->root & PAGE_MASK, self->count, true);
    pmem_unreserve(self->count + self->tables);
    vfree(self, sizeof(*self));
}

static page_t *get_noalloc(anon_mem_object_t *self, uint64_t index, rcu_state_t *state_out) {
    rcu_state_t state = rcu_read_lock();

    uintptr_t root_value = rcu_read(self->root);
    size_t levels = root_value & PAGE_MASK;
    void **curptr = NULL;

    for (;;) {
        void *ptr = curptr ? rcu_read(*curptr) : (void *)(root_value & ~PAGE_MASK);

        if (!ptr) {
            rcu_read_unlock(state);
            return NULL;
        }

        if (levels == 0) {
            if (state_out) *state_out = state;
            else rcu_read_unlock(state);
            return virt_to_page(ptr);
        }

        levels -= 1;
        curptr = (void **)ptr + level_index(index, levels);
    }
}

static hydrogen_ret_t anon_mem_object_get_page(
    mem_object_t *ptr,
    vmm_region_t *region,
    uint64_t index,
    rcu_state_t *state_out,
    bool write
) {
    anon_mem_object_t *self = (anon_mem_object_t *)ptr;

    void *ret = get_noalloc(self, index, state_out);
    if (ret) return ret_pointer(ret);

    // note: can't make this faster by continuing where get_noalloc failed, as the object might've
    // been resized multiple times between rcu being unlocked and the mutex being acquired
    mutex_acq(&self->update_lock, 0, false);

    if (index >= self->count) {
        mutex_rel(&self->update_lock);
        return ret_error(ENXIO);
    }

    uintptr_t root_value = self->root;
    size_t levels = root_value & PAGE_MASK;
    void **curptr = NULL;

    for (;;) {
        void *ptr = curptr ? *curptr : (void *)(root_value & ~PAGE_MASK);

        if (!ptr) {
            ptr = page_to_virt(pmem_alloc());
            memset(ptr, 0, PAGE_SIZE);

            if (curptr) {
                rcu_write(*curptr, ptr);
            } else {
                rcu_write(self->root, (uintptr_t)ptr | levels);
            }
        }

        if (levels == 0) {
            if (state_out) *state_out = rcu_read_lock(); // has to be done before releasing update_lock
            mutex_rel(&self->update_lock);
            return ret_pointer(virt_to_page(ptr));
        }

        levels -= 1;
        curptr = (void **)ptr + level_index(index, levels);
    }
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

static size_t levels_to_tables(size_t levels, size_t count) {
    size_t tables = 0;
    size_t sub_full_tables = 0;

    for (size_t i = levels; i > 0; i--) {
        size_t index = level_index(count - 1, i - 1);
        ASSERT(i != levels || index >= 1);

        tables += sub_full_tables + 1;
        sub_full_tables *= LEVEL_COUNT;
        sub_full_tables += index;
    }

    return tables;
}

int anon_mem_object_init(anon_mem_object_t *object, size_t pages) {
    size_t levels = count_to_levels(pages);
    size_t tables = levels_to_tables(levels, pages);

    size_t nreserve = tables + pages;
    if (nreserve != 0 && unlikely(!pmem_reserve(nreserve))) return ENOMEM;

    object->base.base.ops = &ops.base;
    mem_object_init(&object->base);
    object->root = levels;
    object->count = pages;
    object->tables = tables;

    return 0;
}

int anon_mem_object_create(mem_object_t **out, size_t pages) {
    anon_mem_object_t *object = vmalloc(sizeof(*object));
    if (unlikely(!object)) return ENOMEM;
    memset(object, 0, sizeof(*object));

    int error = anon_mem_object_init(object, pages);
    if (unlikely(error)) {
        vfree(object, sizeof(*object));
        return error;
    }

    *out = &object->base;
    return 0;
}

static int expand_object(anon_mem_object_t *obj, size_t levels, size_t tables, size_t pages) {
    size_t epages = pages - obj->count;
    size_t etables = tables - obj->tables;
    size_t extra = epages + etables;

    if (unlikely(!pmem_reserve(extra))) return ENOMEM;

    void *new_root = (void *)(obj->root & ~PAGE_MASK);

    for (size_t i = obj->root & PAGE_MASK; i < levels; i++) {
        void **table = page_to_virt(pmem_alloc());
        memset(table, 0, PAGE_SIZE);
        table[0] = new_root;
        new_root = table;
    }

    __atomic_store_n(&obj->root, (uintptr_t)new_root | levels, __ATOMIC_RELEASE);
    __atomic_store_n(&obj->count, pages, __ATOMIC_RELEASE);
    obj->tables = tables;
    return 0;
}

#define FREE_HEAD (1u << 0)
#define FREE_TAIL (1u << 1)

static void free_range(shlist_t *list, void *ptr, size_t level, size_t min, size_t max, unsigned flags) {
    if (!ptr) return;

    if (level != 0) {
        void **table = ptr;
        size_t min_idx = (flags & FREE_HEAD) != 0 ? level_index(min, level - 1) : 0;
        size_t max_idx = (flags & FREE_TAIL) != 0 ? level_index(max, level - 1) : LEVEL_COUNT - 1;

        for (size_t i = min_idx; i <= max_idx; i++) {
            unsigned child_flags = 0;

            if ((flags & FREE_HEAD) != 0 && i == min_idx) child_flags |= FREE_HEAD;
            if ((flags & FREE_TAIL) != 0 && i == max_idx) child_flags |= FREE_TAIL;

            free_range(list, table[i], level - 1, min, max, child_flags);
            rcu_write(table[i], NULL);
        }

        if (min_idx != 0) return;
    }

    shlist_insert_head(list, &virt_to_page(ptr)->anon.free_node);
}

static void unmap_object_extras(anon_mem_object_t *obj) {
again: {
    uint64_t unmap_offset = (uint64_t)obj->count << PAGE_SHIFT;
    mutex_acq(&obj->base.regions_lock, 0, false);

    LIST_FOREACH(obj->base.regions, vmm_region_t, object_node, region) {
        uint64_t tail_offset = region->offset + (region->tail - region->head);
        if (tail_offset < unmap_offset) continue;

        vmm_t *vmm = region->vmm;

        if (!rmutex_try_acq(&vmm->lock)) {
            obj_ref(&vmm->base);
            mutex_rel(&obj->base.regions_lock);
            mutex_rel(&obj->update_lock);
            rmutex_acq(&vmm->lock, 0, false);
            rmutex_rel(&vmm->lock);
            obj_deref(&vmm->base);
            mutex_acq(&obj->update_lock, 0, false);
            goto again;
        }

        uintptr_t unmap_head = region->head + (unmap_offset - region->offset);
        pmap_rmmap(vmm, unmap_head, region->tail - unmap_head + 1);
    }

    mutex_rel(&obj->base.regions_lock);
}
}

int anon_mem_object_resize(mem_object_t *ptr, size_t pages) {
    anon_mem_object_t *obj = (anon_mem_object_t *)ptr;

    size_t levels = count_to_levels(pages);
    size_t tables = levels_to_tables(levels, pages);

    mutex_acq(&obj->update_lock, 0, false);

    if (pages == obj->count) {
        mutex_rel(&obj->update_lock);
        return 0;
    }

    if (pages > obj->count) {
        int error = expand_object(obj, levels, tables, pages);
        mutex_rel(&obj->update_lock);
        return error;
    }

    size_t old_pages = pages;
    size_t old_tables = tables;
    shlist_t free_queue = {};

    uintptr_t root_addr = obj->root & ~PAGE_MASK;
    size_t cur_levels = obj->root & PAGE_MASK;
    ASSERT(cur_levels >= levels);

    // Build free queue
    free_range(&free_queue, (void *)root_addr, cur_levels, pages, obj->count - 1, FREE_HEAD | FREE_TAIL);

    // Reduce number of levels
    if (pages != 0) {
        while (cur_levels > levels) {
            if (!root_addr) {
                cur_levels = levels;
                break;
            }

            void **table = (void **)root_addr;
            root_addr = (uintptr_t)table[0];
            cur_levels -= 1;
            shlist_insert_head(&free_queue, &virt_to_page(table)->anon.free_node);
        }
    } else {
        root_addr = 0;
        cur_levels = 0;
    }

    // Commit changes
    rcu_write(obj->root, root_addr | cur_levels);
    obj->count = pages;
    obj->tables = tables;
    unmap_object_extras(obj);
    mutex_rel(&obj->update_lock);
    rcu_sync();

    // Free pages
    SHLIST_FOREACH(free_queue, page_t, anon.free_node, page) {
        pmem_free(page);
    }

    pmem_unreserve((old_pages - pages) + (old_tables - tables));
    return 0;
}

bool is_anon_mem_object(mem_object_t *obj) {
    return obj->base.ops == &ops.base;
}
