#include "mem/vmm.h"
#include "arch/pmap.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "fs/vfs.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "kernel/return.h"
#include "mem/memmap.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/vmalloc.h"
#include "proc/mutex.h"
#include "proc/rcu.h"
#include "proc/sched.h"
#include "string.h"
#include "sys/vdso.h"
#include "util/list.h"
#include "util/object.h"
#include <hydrogen/memory.h>
#include <hydrogen/types.h>
#include <stdint.h>

static void replace_child(vmm_t *vmm, vmm_region_t *parent, vmm_region_t *from, vmm_region_t *to) {
    to->parent = parent;

    if (parent) {
        if (parent->left == from) {
            parent->left = to;
        } else {
            parent->right = to;
        }
    } else {
        vmm->regtree = to;
    }
}

static vmm_region_t *rotate_left(vmm_t *vmm, vmm_region_t *root, vmm_region_t *right) {
    vmm_region_t *parent = root->parent;

    vmm_region_t *new_right = right->left;
    root->right = new_right;
    if (new_right) new_right->parent = root;

    right->left = root;
    root->parent = right;

    if (right->balance == 0) {
        root->balance = 1;
        right->balance = -1;
    } else {
        root->balance = 0;
        right->balance = 0;
    }

    replace_child(vmm, parent, root, right);
    return right;
}

static vmm_region_t *rotate_right(vmm_t *vmm, vmm_region_t *root, vmm_region_t *left) {
    vmm_region_t *parent = root->parent;

    vmm_region_t *new_left = left->right;
    root->left = new_left;
    if (new_left) new_left->parent = root;

    left->right = root;
    root->parent = left;

    if (left->balance == 0) {
        root->balance = -1;
        left->balance = 1;
    } else {
        root->balance = 0;
        left->balance = 0;
    }

    replace_child(vmm, parent, root, left);
    return left;
}

static vmm_region_t *rotate_left_right(vmm_t *vmm, vmm_region_t *root, vmm_region_t *left) {
    vmm_region_t *parent = root->parent;
    vmm_region_t *new_root = left->right;

    vmm_region_t *new_left_right = new_root->left;
    left->right = new_left_right;
    if (new_left_right) new_left_right->parent = left;

    new_root->left = left;
    left->parent = new_root;

    vmm_region_t *new_right_left = new_root->right;
    root->left = new_right_left;
    if (new_right_left) new_right_left->parent = root;

    new_root->right = root;
    root->parent = new_root;

    if (new_root->balance == 0) {
        root->balance = 0;
        left->balance = 0;
    } else if (new_root->balance > 0) {
        root->balance = 1;
        left->balance = 0;
    } else {
        root->balance = 0;
        left->balance = -1;
    }

    new_root->balance = 0;
    replace_child(vmm, parent, root, new_root);
    return new_root;
}

static vmm_region_t *rotate_right_left(vmm_t *vmm, vmm_region_t *root, vmm_region_t *right) {
    vmm_region_t *parent = root->parent;
    vmm_region_t *new_root = right->left;

    vmm_region_t *new_right_left = new_root->right;
    right->left = new_right_left;
    if (new_right_left) new_right_left->parent = right;

    new_root->right = right;
    right->parent = new_root;

    vmm_region_t *new_left_right = new_root->left;
    root->right = new_left_right;
    if (new_left_right) new_left_right->parent = root;

    new_root->left = root;
    root->parent = new_root;

    if (new_root->balance == 0) {
        root->balance = 0;
        right->balance = 0;
    } else if (new_root->balance > 0) {
        root->balance = -1;
        right->balance = 0;
    } else {
        root->balance = 0;
        right->balance = 1;
    }

    new_root->balance = 0;
    replace_child(vmm, parent, root, new_root);
    return new_root;
}

static void tree_add(vmm_t *vmm, vmm_region_t *region) {
    vmm_region_t *parent = NULL;
    vmm_region_t **field = &vmm->regtree;
    vmm_region_t *cur = *field;

    // find location to insert at
    while (cur) {
        if (region->head <= cur->head) {
            field = &cur->left;
        } else {
            field = &cur->right;
        }

        parent = cur;
        cur = *field;
    }

    // perform insertion
    region->parent = parent;
    region->left = NULL;
    region->right = NULL;
    region->balance = 0;
    *field = region;

    // rebalance tree
    while (parent) {
        if (region == parent->left) {
            parent->balance -= 1;

            if (parent->balance == -2) {
                if (region->balance > 0) {
                    parent = rotate_left_right(vmm, parent, region);
                } else {
                    parent = rotate_right(vmm, parent, region);
                }
            }
        } else {
            parent->balance += 1;

            if (parent->balance == 2) {
                if (region->balance < 0) {
                    parent = rotate_right_left(vmm, parent, region);
                } else {
                    parent = rotate_left(vmm, parent, region);
                }
            }
        }

        if (parent->balance == 0) break;

        region = parent;
        parent = parent->parent;
    }
}

static void tree_del(vmm_t *vmm, vmm_region_t *region) {
retry: {
    vmm_region_t *parent = region->parent;
    vmm_region_t **field;

    if (parent) {
        if (region == parent->left) field = &parent->left;
        else field = &parent->right;
    } else {
        field = &vmm->regtree;
    }

    if (!region->left && !region->right) {
        *field = NULL;
    } else if (!region->left) {
        *field = region->right;
        (*field)->parent = parent;
    } else if (!region->right) {
        *field = region->left;
        (*field)->parent = parent;
    } else {
        // swap with successor and retry
        vmm_region_t *successor = region->right;
        while (successor->left) successor = successor->left;

        vmm_region_t *orig_right = successor->right;
        int orig_balance = successor->balance;

        successor->left = region->left;
        successor->left->parent = successor;
        successor->balance = region->balance;

        if (region->right != successor) {
            successor->right = region->right;

            successor->parent->left = region;
            region->parent = successor->parent;
        } else {
            successor->right = region;
        }

        successor->right->parent = successor;
        successor->parent = parent;

        region->left = NULL;
        region->right = orig_right;
        if (region->right) region->right->parent = region;
        region->balance = orig_balance;

        *field = successor;
        goto retry;
    }

    // rebalance tree

    while (parent != NULL) {
        if (field == &parent->left) {
            parent->balance += 1;

            if (parent->balance == 2) {
                vmm_region_t *right = parent->right;

                if (right->balance < 0) {
                    parent = rotate_right_left(vmm, parent, right);
                } else {
                    parent = rotate_left(vmm, parent, right);
                }
            }
        } else {
            parent->balance -= 1;

            if (parent->balance == -2) {
                vmm_region_t *left = parent->left;

                if (left->balance > 0) {
                    parent = rotate_left_right(vmm, parent, left);
                } else {
                    parent = rotate_right(vmm, parent, left);
                }
            }
        }

        if (parent->balance != 0) break;

        parent = parent->parent;
    }
}
}

static void tree_mov(vmm_t *vmm, vmm_region_t *region, uintptr_t new_head) {
    tree_del(vmm, region);
    region->head = new_head;
    tree_add(vmm, region);
}

static void vmm_free(object_t *ptr) {
    vmm_t *vmm = (vmm_t *)ptr;

    pmap_prepare_destroy(&vmm->pmap);

    for (;;) {
        vmm_region_t *region = LIST_REMOVE_HEAD(vmm->regions, vmm_region_t, node);
        if (!region) break;
        pmap_destroy_range(vmm, region->head, region->tail - region->head + 1);
        vfree(region, sizeof(*region));
    }

    pmap_finish_destruction(vmm);
    pmem_unreserve(vmm->num_reserved);

    if (vmm->path) dentry_deref(vmm->path);
    if (vmm->inode) inode_deref(vmm->inode);

    vfree(vmm, sizeof(*vmm));
}

static const object_ops_t vmm_object_ops = {.free = vmm_free};

int vmm_create(vmm_t **out) {
    static uint64_t next_id = 1;

    vmm_t *vmm = vmalloc(sizeof(*vmm));
    if (unlikely(!vmm)) return ENOMEM;
    memset(vmm, 0, sizeof(*vmm));

    int error = pmap_create(vmm);
    if (unlikely(error)) {
        vfree(vmm, sizeof(*vmm));
        return error;
    }

    vmm->base.ops = &vmm_object_ops;
    obj_init(&vmm->base, OBJECT_VMM);
    vmm->id = __atomic_fetch_add(&next_id, 1, __ATOMIC_RELAXED);

    *out = vmm;
    return 0;
}

static void obj_add(vmm_region_t *region) {
    if (!region->object) return;

    obj_ref(&region->object->base);
    mutex_acq(&region->object->regions_lock, 0, false);
    list_insert_tail(&region->object->regions, &region->object_node);
    mutex_rel(&region->object->regions_lock);
}

static void obj_add_two(vmm_region_t *r1, vmm_region_t *r2) {
    ASSERT(r1->object == r2->object);
    if (!r1->object) return;

    obj_ref_n(&r1->object->base, 2);
    mutex_acq(&r1->object->regions_lock, 0, false);
    list_insert_tail(&r1->object->regions, &r1->object_node);
    list_insert_tail(&r1->object->regions, &r2->object_node);
    mutex_rel(&r1->object->regions_lock);
}

static void obj_rem(vmm_region_t *region) {
    if (!region->object) return;

    mutex_acq(&region->object->regions_lock, 0, false);
    list_remove(&region->object->regions, &region->object_node);
    mutex_rel(&region->object->regions_lock);
    obj_deref(&region->object->base);
}

static void obj_rem_two(vmm_region_t *r1, vmm_region_t *r2) {
    ASSERT(r1->object == r2->object);
    if (!r1->object) return;

    mutex_acq(&r1->object->regions_lock, 0, false);
    list_remove(&r1->object->regions, &r1->object_node);
    list_remove(&r1->object->regions, &r2->object_node);
    mutex_rel(&r1->object->regions_lock);
    obj_deref_n(&r1->object->base, 2);
}

int clone_region(vmm_region_t **out, vmm_t *dvmm, vmm_t *svmm, vmm_region_t *src) {
    vmm_region_t *dst = vmalloc(sizeof(*dst));
    if (unlikely(!dst)) return ENOMEM;
    memset(dst, 0, sizeof(*dst));

    dst->vmm = dvmm;
    dst->head = src->head;
    dst->tail = src->tail;
    dst->flags = src->flags;
    dst->object = src->object;
    dst->rights = src->rights;
    dst->offset = src->offset;

    if (unlikely(!pmap_prepare(dvmm, dst->head, dst->tail - dst->head + 1))) {
        vfree(dst, sizeof(*dst));
        return ENOMEM;
    }

    obj_add(dst);

    pmap_clone(svmm, dvmm, dst->head, dst->tail - dst->head + 1, (dst->flags & HYDROGEN_MEM_SHARED) == 0);
    *out = dst;
    return 0;
}

static int clone_regions(vmm_t *dst, vmm_t *src) {
    LIST_FOREACH(src->regions, vmm_region_t, node, region) {
        vmm_region_t *dreg;
        int error = clone_region(&dreg, dst, src, region);
        if (unlikely(error)) return error;

        list_insert_tail(&dst->regions, &dreg->node);
        tree_add(dst, dreg);
    }

    return 0;
}

int vmm_clone(vmm_t **out, vmm_t *src) {
    vmm_t *vmm;
    int error = vmm_create(&vmm);
    if (unlikely(error)) return error;

    rmutex_acq(&src->lock, 0, false);

    if (src->num_reserved != 0 && unlikely(!pmem_reserve(src->num_reserved))) {
        rmutex_rel(&src->lock);
        obj_deref(&vmm->base);
        return ENOMEM;
    }

    vmm->num_mapped = src->num_mapped;
    vmm->num_reserved = src->num_reserved;
    vmm->vdso_addr = src->vdso_addr;

    error = clone_regions(vmm, src);
    rmutex_rel(&src->lock);
    if (unlikely(error)) {
        obj_deref(&vmm->base);
        return error;
    }

    *out = vmm;
    return 0;
}

vmm_t *vmm_switch(vmm_t *vmm) {
    vmm_t *orig = current_thread->vmm;
    current_thread->vmm = vmm;

    if (vmm != NULL) {
        preempt_state_t state = preempt_lock();
        pmap_switch(&vmm->pmap);
        preempt_unlock(state);
    }

    return orig;
}

static void get_nonoverlap_bounds(
    vmm_t *vmm,
    uintptr_t head,
    uintptr_t tail,
    vmm_region_t **prev_out,
    vmm_region_t **next_out
) {
    vmm_region_t *prev = NULL;
    vmm_region_t *next = LIST_HEAD(vmm->regions, vmm_region_t, node);

    while (next && next->tail < head) {
        prev = next;
        next = LIST_NEXT(*next, vmm_region_t, node);
    }

    while (next && next->head <= tail) {
        next = LIST_NEXT(*next, vmm_region_t, node);
    }

    *prev_out = prev;
    *next_out = next;
}

static vmm_region_t *get_next(vmm_t *vmm, vmm_region_t *prev) {
    return prev ? LIST_NEXT(*prev, vmm_region_t, node) : LIST_HEAD(vmm->regions, vmm_region_t, node);
}

static void process_unmap(vmm_t *vmm, uintptr_t head, uintptr_t tail, bool reserved, bool remove_instead_of_unmap) {
    size_t pages = (tail - head + 1) >> PAGE_SHIFT;

    if (remove_instead_of_unmap) pmap_rmmap(vmm, head, tail - head + 1);
    else pmap_unmap(vmm, head, tail - head + 1);

    vmm->num_mapped -= pages;
    if (reserved) vmm->num_reserved -= reserved;
}

static bool need_reserve_memory(unsigned flags) {
    return (flags & (HYDROGEN_MEM_SHARED | HYDROGEN_MEM_LAZY_RESERVE)) == 0;
}

static int remove_overlapping_regions(
    vmm_t *vmm,
    vmm_region_t **prev_inout,
    vmm_region_t **next_inout,
    uintptr_t head,
    uintptr_t tail,
    bool remove_instead_of_unmap
) {
    vmm_region_t *prev = *prev_inout;
    vmm_region_t *next = *next_inout;

    vmm_region_t *cur = get_next(vmm, prev);

    // check for errors before actually doing anything
    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        if (cur->object == &vdso_object) {
            return EACCES;
        }

        cur = LIST_NEXT(*cur, vmm_region_t, node);
    }

    cur = get_next(vmm, prev);

    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        if (cur->head < head && cur->tail > tail) {
            // Needs to be split into two
            ASSERT(LIST_PREV(*cur, vmm_region_t, node) == prev);
            ASSERT(LIST_NEXT(*cur, vmm_region_t, node) == next);

            vmm_region_t *nreg = vmalloc(sizeof(*nreg));
            if (unlikely(!nreg)) return ENOMEM;
            memset(nreg, 0, sizeof(*nreg));

            process_unmap(vmm, head, tail, need_reserve_memory(cur->flags), remove_instead_of_unmap);

            nreg->vmm = vmm;
            nreg->head = tail + 1;
            nreg->tail = cur->tail;
            nreg->flags = cur->flags;
            nreg->object = cur->object;
            nreg->rights = cur->rights;
            nreg->offset = cur->offset + (nreg->head - cur->head);
            obj_add(nreg);

            cur->tail = head - 1;

            tree_add(vmm, nreg);
            list_insert_after(&vmm->regions, &cur->node, &nreg->node);

            *prev_inout = cur;
            *next_inout = nreg;
            return 0;
        } else if (cur->head < head) {
            // Needs to be truncated
            ASSERT(LIST_PREV(*cur, vmm_region_t, node) == prev);
            process_unmap(vmm, head, cur->tail, need_reserve_memory(cur->flags), remove_instead_of_unmap);

            cur->tail = head - 1;

            *prev_inout = cur;
            cur = LIST_NEXT(*cur, vmm_region_t, node);
        } else if (cur->tail > tail) {
            // Needs to be truncated and moved
            ASSERT(LIST_NEXT(*cur, vmm_region_t, node) == next);
            process_unmap(vmm, cur->head, tail, need_reserve_memory(cur->flags), remove_instead_of_unmap);

            tree_mov(vmm, cur, tail + 1);

            *next_inout = cur;
            return 0;
        } else {
            // Needs to be completely removed
            process_unmap(vmm, cur->head, cur->tail, need_reserve_memory(cur->flags), remove_instead_of_unmap);

            vmm_region_t *n = LIST_NEXT(*cur, vmm_region_t, node);

            tree_del(vmm, cur);
            list_remove(&vmm->regions, &cur->node);

            obj_rem(cur);
            vfree(cur, sizeof(*cur));

            cur = n;
        }
    }

    return 0;
}

static bool can_merge(vmm_region_t *r1, vmm_region_t *r2) {
    if (!r1 || !r2) return false;
    ASSERT(r1->head < r2->head);

    if (r1->tail + 1 != r2->head) return false;
    if (r1->flags != r2->flags) return false;

    if (r1->object != NULL) {
        if (r1->object != r2->object) return false;
        if (r1->rights != r2->rights) return false;
        if (r1->offset + (r2->head - r1->head) != r2->offset) return false;
    }

    return true;
}

// might free `region`
static vmm_region_t *merge_or_insert(vmm_t *vmm, vmm_region_t *prev, vmm_region_t *next, vmm_region_t *region) {
    bool prev_merge = can_merge(prev, region);
    bool next_merge = can_merge(region, next);

    if (prev_merge && next_merge) {
        prev->tail = next->tail;

        tree_del(vmm, next);
        list_remove(&vmm->regions, &next->node);

        obj_rem_two(region, next);
        vfree(region, sizeof(*region));
        vfree(next, sizeof(*next));
        return prev;
    } else if (prev_merge) {
        prev->tail = region->tail;

        obj_rem(region);
        vfree(region, sizeof(*region));
        return prev;
    } else if (next_merge) {
        tree_mov(vmm, next, region->head);

        obj_rem(region);
        vfree(region, sizeof(*region));
        return next;
    } else {
        tree_add(vmm, region);
        list_insert_after(&vmm->regions, prev ? &prev->node : NULL, &region->node);
        return region;
    }
}

static int do_map(
    vmm_t *vmm,
    uintptr_t head,
    uintptr_t tail,
    unsigned flags,
    mem_object_t *object,
    object_rights_t rights,
    size_t offset,
    vmm_region_t *prev,
    vmm_region_t *next
) {
    size_t pages = (tail - head + 1) >> PAGE_SHIFT;

    vmm_region_t *region = vmalloc(sizeof(*region));
    if (unlikely(!region)) return ENOMEM;
    memset(region, 0, sizeof(*region));

    region->vmm = vmm;
    region->head = head;
    region->tail = tail;
    region->flags = flags & VMM_REGION_FLAGS;
    region->object = object;
    region->rights = rights;
    region->offset = offset;

    bool reserve = need_reserve_memory(flags);
    if (reserve && unlikely(!pmem_reserve(pages))) {
        vfree(region, sizeof(*region));
        return ENOMEM;
    }

    if (unlikely(!pmap_prepare(vmm, head, tail - head + 1))) {
        if (reserve) pmem_unreserve(pages);
        vfree(region, sizeof(*region));
        return ENOMEM;
    }

    int error = remove_overlapping_regions(vmm, &prev, &next, head, tail, true);
    if (unlikely(error)) {
        pmap_unmap(vmm, head, tail - head + 1);
        if (reserve) pmem_unreserve(pages);
        vfree(region, sizeof(*region));
        return error;
    }

    obj_add(region);
    merge_or_insert(vmm, prev, next, region);

    vmm->num_mapped += pages;
    if (reserve) vmm->num_reserved += pages;

    if (object != NULL) {
        const mem_object_ops_t *ops = (const mem_object_ops_t *)object->base.ops;

        if (ops->post_map != NULL) {
            ops->post_map(object, vmm, head, tail, flags, offset);
        }
    }

    return 0;
}

static int try_map_exact(
    vmm_t *vmm,
    uintptr_t head,
    size_t size,
    unsigned flags,
    mem_object_t *object,
    object_rights_t rights,
    size_t offset
) {
    if (unlikely(head < PAGE_SIZE)) return ENOMEM;

    uintptr_t tail = head + (size - 1);
    if (unlikely(head > tail)) return ENOMEM;
    if (unlikely(tail > arch_pt_max_user_addr())) return ENOMEM;

    vmm_region_t *prev, *next;
    get_nonoverlap_bounds(vmm, head, tail, &prev, &next);

    if ((flags & HYDROGEN_MEM_OVERWRITE) == 0 && get_next(vmm, prev) != next) return EEXIST;

    return do_map(vmm, head, tail, flags, object, rights, offset, prev, next);
}

static uintptr_t get_tail(vmm_region_t *region) {
    return region ? region->tail : PAGE_MASK;
}

static uintptr_t get_head(vmm_region_t *region) {
    return region ? region->head : arch_pt_max_user_addr();
}

static int find_map_location(
    vmm_t *vmm,
    size_t size,
    vmm_region_t **prev_out,
    vmm_region_t **next_out,
    uintptr_t *head_out,
    uintptr_t *tail_out
) {
    vmm_region_t *prev = NULL;
    vmm_region_t *next = LIST_HEAD(vmm->regions, vmm_region_t, node);

    for (;;) {
        size_t avail = get_head(next) - get_tail(prev) + 1;
        if (avail >= size) break;

        if (!next) return ENOMEM;

        prev = next;
        next = LIST_NEXT(*next, vmm_region_t, node);
    }

    uintptr_t head = get_tail(prev) + 1;
    uintptr_t tail = head + (size - 1);

    *prev_out = prev;
    *next_out = next;
    *head_out = head;
    *tail_out = tail;

    return 0;
}

#define SHARED_WRITE (HYDROGEN_MEM_SHARED | HYDROGEN_MEM_WRITE)

static bool check_rights(object_rights_t rights, unsigned flags) {
    if ((flags & HYDROGEN_MEM_READ) != 0 && (rights & HYDROGEN_MEM_OBJECT_READ) == 0) return false;
    if ((flags & SHARED_WRITE) == SHARED_WRITE && (rights & HYDROGEN_MEM_OBJECT_WRITE) == 0) return false;
    if ((flags & HYDROGEN_MEM_EXEC) != 0 && (rights & HYDROGEN_MEM_OBJECT_EXEC) == 0) return false;
    return true;
}

hydrogen_ret_t vmm_map(
    vmm_t *vmm,
    uintptr_t hint,
    size_t size,
    unsigned flags,
    mem_object_t *object,
    object_rights_t rights,
    size_t offset
) {
    ASSERT(object != &vdso_object);

    if (unlikely(((hint | size) & PAGE_MASK) != 0)) return ret_error(EINVAL);
    if (unlikely((flags & ~VMM_MAP_FLAGS) != 0)) return ret_error(EINVAL);
    if (unlikely(size == 0)) return ret_error(EINVAL);
    if (unlikely((flags & (HYDROGEN_MEM_EXACT | HYDROGEN_MEM_OVERWRITE)) == HYDROGEN_MEM_OVERWRITE)) {
        return ret_error(EINVAL);
    }

    if (object != NULL) {
        if (unlikely((offset & PAGE_MASK) != 0)) return ret_error(EINVAL);
        if (unlikely(offset > offset + (size - 1))) return ret_error(EINVAL);
        if (unlikely(!check_rights(rights, flags))) return ret_error(EACCES);

        const mem_object_ops_t *ops = (const mem_object_ops_t *)object->base.ops;

        if (ops->get_page == NULL) {
            if (unlikely((flags & HYDROGEN_MEM_SHARED) == 0)) return ret_error(EINVAL);
        }
    } else if (unlikely((flags & HYDROGEN_MEM_SHARED) != 0)) {
        return ret_error(EINVAL);
    }

    rmutex_acq(&vmm->lock, 0, false);

    int error = try_map_exact(vmm, hint, size, flags, object, rights, offset);
    if (error == 0 || (flags & HYDROGEN_MEM_EXACT) != 0) goto ret;

    vmm_region_t *prev, *next;
    uintptr_t head, tail;
    error = find_map_location(vmm, size, &prev, &next, &head, &tail);
    if (unlikely(error)) goto ret;

    error = do_map(vmm, head, tail, flags, object, rights, offset, prev, next);
ret:
    rmutex_rel(&vmm->lock);
    return RET_MAYBE(integer, error, head);
}

hydrogen_ret_t vmm_map_vdso(vmm_t *vmm) {
    rmutex_acq(&vmm->lock, 0, false);

    if (vmm->vdso_addr != 0) {
        rmutex_rel(&vmm->lock);
        return ret_error(EINVAL);
    }

    vmm_region_t *prev, *next;
    uintptr_t head, tail;
    int error = find_map_location(vmm, vdso_size, &prev, &next, &head, &tail);
    if (unlikely(error)) goto ret;

    error = do_map(
        vmm,
        head,
        tail,
        HYDROGEN_MEM_READ | HYDROGEN_MEM_EXEC | HYDROGEN_MEM_SHARED,
        &vdso_object,
        HYDROGEN_MEM_OBJECT_READ | HYDROGEN_MEM_OBJECT_EXEC,
        0,
        prev,
        next
    );
    if (likely(error == 0)) __atomic_store_n(&vmm->vdso_addr, head + vdso_image_offset, __ATOMIC_RELAXED);
ret:
    rmutex_rel(&vmm->lock);
    return RET_MAYBE(integer, error, head + vdso_image_offset);
}

static int split_to_exact(
    vmm_t *vmm,
    vmm_region_t *prev,
    vmm_region_t *next,
    uintptr_t head,
    uintptr_t tail,
    int (*check_cb)(vmm_region_t *, void *), /* returns 1 if the region should be skipped. negative = error code */
    bool (*skip_cb)(vmm_region_t *, void *), /* must return true if and only if check_cb returned 1 */
    void (*final_cb)(vmm_t *, vmm_region_t *, void *),
    void *ctx
) {
    vmm_region_t *cur = get_next(vmm, prev);
    size_t extra_regions = 0;

    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        if (cur->object == &vdso_object) {
            return EACCES;
        }

        int ret = check_cb(cur, ctx);
        if (unlikely(ret < 0)) return -ret;

        if (likely(ret == 0)) {
            if (cur->head < head) extra_regions += 1;
            if (cur->tail > tail) extra_regions += 1;
        }

        cur = LIST_NEXT(*cur, vmm_region_t, node);
    }

    ASSERT(extra_regions <= 2);
    vmm_region_t *regions[2];

    for (size_t i = 0; i < extra_regions; i++) {
        regions[i] = vmalloc(sizeof(*regions[i]));

        if (unlikely(!regions[i])) {
            for (size_t j = 0; j < i; j++) {
                vfree(regions[j], sizeof(*regions[j]));
            }

            return ENOMEM;
        }

        memset(regions[i], 0, sizeof(*regions[i]));
    }

    cur = get_next(vmm, prev);

    // No errors allowed from now on

    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        if (skip_cb(cur, ctx)) {
            cur = LIST_NEXT(*cur, vmm_region_t, node);
            continue;
        }

        vmm_region_t *region;

        if (cur->head < head && cur->tail > tail) {
            // Needs to be split into three
            ASSERT(extra_regions >= 2);
            ASSERT(LIST_PREV(*cur, vmm_region_t, node) == prev);
            ASSERT(LIST_NEXT(*cur, vmm_region_t, node) == next);

            extra_regions -= 2;
            vmm_region_t **new_regions = &regions[extra_regions];

            new_regions[0]->vmm = vmm;
            new_regions[0]->head = head;
            new_regions[0]->tail = tail;
            new_regions[0]->flags = cur->flags;
            new_regions[0]->object = cur->object;
            new_regions[0]->rights = cur->rights;
            new_regions[0]->offset = cur->offset + (new_regions[0]->head - cur->head);

            new_regions[1]->vmm = vmm;
            new_regions[1]->head = tail + 1;
            new_regions[1]->tail = cur->tail;
            new_regions[1]->flags = cur->flags;
            new_regions[1]->object = cur->object;
            new_regions[1]->rights = cur->rights;
            new_regions[1]->offset = cur->offset + (new_regions[1]->head - cur->head);

            obj_add_two(new_regions[0], new_regions[1]);

            cur->tail = head - 1;
            tree_add(vmm, new_regions[0]);
            tree_add(vmm, new_regions[1]);
            list_insert_after(&vmm->regions, &cur->node, &new_regions[0]->node);
            list_insert_after(&vmm->regions, &new_regions[0]->node, &new_regions[1]->node);

            region = new_regions[0];
            cur = new_regions[1];
        } else if (cur->head < head) {
            // Needs to be split into two
            ASSERT(extra_regions >= 1);
            ASSERT(LIST_PREV(*cur, vmm_region_t, node) == prev);

            region = regions[--extra_regions];

            region->vmm = vmm;
            region->head = head;
            region->tail = cur->tail;
            region->flags = cur->flags;
            region->object = cur->object;
            region->rights = cur->rights;
            region->offset = cur->offset + (region->head - cur->head);
            obj_add(region);

            cur->tail = head - 1;
            tree_add(vmm, region);
            list_insert_after(&vmm->regions, &cur->node, &region->node);
        } else if (cur->tail > tail) {
            // Needs to be split into two
            ASSERT(extra_regions >= 1);
            ASSERT(LIST_NEXT(*cur, vmm_region_t, node) == next);

            region = cur;
            cur = regions[--extra_regions];

            cur->vmm = vmm;
            cur->head = tail + 1;
            cur->tail = region->tail;
            cur->flags = region->flags;
            cur->object = region->object;
            cur->rights = region->rights;
            cur->offset = region->offset + (cur->head - region->head);
            obj_add(cur);

            region->tail = tail;
            tree_add(vmm, cur);
            list_insert_after(&vmm->regions, &region->node, &cur->node);
        } else {
            region = cur;
        }

        cur = LIST_NEXT(*cur, vmm_region_t, node);
        final_cb(vmm, region, ctx);
    }

    ASSERT(extra_regions == 0);
    return 0;
}

static int remap_check_cb(vmm_region_t *region, void *ctx) {
    unsigned new_flags = (region->flags & ~VMM_PERM_FLAGS) | (uintptr_t)ctx;
    if (new_flags == region->flags) return 1;

    if (region->object != NULL) {
        if (unlikely(!check_rights(region->rights, new_flags))) return -EACCES;
    }

    return 0;
}

static bool remap_skip_cb(vmm_region_t *region, void *ctx) {
    unsigned new_flags = (region->flags & ~VMM_PERM_FLAGS) | (uintptr_t)ctx;
    return new_flags == region->flags;
}

static void remap_final_cb(vmm_t *vmm, vmm_region_t *region, void *ctx) {
    unsigned new_flags = (region->flags & ~VMM_PERM_FLAGS) | (uintptr_t)ctx;
    region->flags = new_flags;
    pmap_remap(vmm, region->head, region->tail - region->head + 1, vmm_to_pmap_flags(region->flags));
}

static int do_remap(
    vmm_t *vmm,
    vmm_region_t *prev,
    vmm_region_t *next,
    uintptr_t head,
    uintptr_t tail,
    unsigned flags
) {
    return split_to_exact(
        vmm,
        prev,
        next,
        head,
        tail,
        remap_check_cb,
        remap_skip_cb,
        remap_final_cb,
        (void *)(uintptr_t)flags
    );
}

int vmm_remap(vmm_t *vmm, uintptr_t address, size_t size, unsigned flags) {
    if (unlikely(((address | size) & PAGE_MASK) != 0)) return EINVAL;
    if (unlikely(size == 0)) return EINVAL;
    if (unlikely((flags & ~VMM_PERM_FLAGS) != 0)) return EINVAL;

    uintptr_t tail = address + (size - 1);
    if (unlikely(address > tail)) tail = UINTPTR_MAX;

    rmutex_acq(&vmm->lock, 0, false);

    vmm_region_t *prev, *next;
    get_nonoverlap_bounds(vmm, address, tail, &prev, &next);

    int error = do_remap(vmm, prev, next, address, tail, flags);
    rmutex_rel(&vmm->lock);
    return error;
}

struct move_ctx {
    vmm_region_t *first;
    vmm_region_t *last;
};

static int move_check_cb(vmm_region_t *region, UNUSED void *ptr) {
    return 0;
}

static bool move_skip_cb(UNUSED vmm_region_t *region, UNUSED void *ptr) {
    return false;
}

static void move_final_cb(vmm_t *vmm, vmm_region_t *region, void *ptr) {
    struct move_ctx *ctx = ptr;

    tree_del(vmm, region);
    list_remove(&vmm->regions, &region->node);

    if (!ctx->first) ctx->first = region;
    ctx->last = region;
}

hydrogen_ret_t vmm_move(
    vmm_t *vmm,
    uintptr_t addr,
    size_t size,
    vmm_t *dest_vmm,
    uintptr_t dest_addr,
    size_t dest_size
) {
    if (unlikely(((addr | dest_addr | size | dest_size) & PAGE_MASK) != 0)) return ret_error(EINVAL);
    if (unlikely(addr < PAGE_SIZE)) return ret_error(EINVAL);
    if (unlikely(size == 0)) return ret_error(EINVAL);
    if (unlikely(size > dest_size)) return ret_error(EINVAL);

    uintptr_t tail = addr + (size - 1);
    if (unlikely(addr > tail)) return ret_error(EINVAL);
    if (unlikely(tail > arch_pt_max_user_addr())) return ret_error(EINVAL);

    uintptr_t dest_tail;

    if (dest_addr != 0) {
        if (unlikely(dest_addr < PAGE_SIZE)) return ret_error(EINVAL);
        dest_tail = dest_addr + (dest_size - 1);
        if (unlikely(dest_addr > dest_tail)) return ret_error(EINVAL);
        if (unlikely(dest_tail > arch_pt_max_user_addr())) return ret_error(EINVAL);
    }

    if (vmm == dest_vmm) {
        rmutex_acq(&vmm->lock, 0, false);
    } else if ((uintptr_t)vmm < (uintptr_t)dest_vmm) {
        rmutex_acq(&vmm->lock, 0, false);
        rmutex_acq(&dest_vmm->lock, 0, false);
    } else {
        rmutex_acq(&dest_vmm->lock, 0, false);
        rmutex_acq(&vmm->lock, 0, false);
    }

    vmm_region_t *dst_prev, *dst_next;
    int error;

    if (dest_addr != 0) {
        get_nonoverlap_bounds(dest_vmm, dest_addr, dest_tail, &dst_prev, &dst_next);
        if (unlikely(get_next(dest_vmm, dst_prev) != dst_next)) {
            error = EEXIST;
            goto ret;
        }
    } else {
        error = find_map_location(dest_vmm, dest_size, &dst_prev, &dst_next, &dest_addr, &dest_tail);
        if (unlikely(error)) goto ret;
    }

    vmm_region_t *extra_region;
    size_t extra;

    if (size < dest_size) {
        extra_region = vmalloc(sizeof(*extra_region));
        if (unlikely(!extra_region)) {
            error = ENOMEM;
            goto ret;
        }

        extra = (dest_size - size) >> PAGE_SHIFT;
        if (unlikely(!pmem_reserve(extra))) {
            vfree(extra_region, sizeof(*extra_region));
            error = ENOMEM;
            goto ret;
        }
    } else {
        extra = 0;
    }

    vmm_region_t *prev, *next;
    get_nonoverlap_bounds(vmm, addr, tail, &prev, &next);

    struct move_ctx ctx = {};
    error = split_to_exact(vmm, prev, next, addr, tail, move_check_cb, move_skip_cb, move_final_cb, &ctx);

    if (unlikely(error)) {
        if (extra != 0) {
            pmem_unreserve(extra);
            vfree(extra_region, sizeof(*extra_region));
        }

        goto ret;
    }

    // get bounds again since the pointers may have changed in split_to_exact
    get_nonoverlap_bounds(dest_vmm, dest_addr, dest_tail, &dst_prev, &dst_next);

    uintptr_t offset = dest_addr - addr;

    while (ctx.first) {
        vmm_region_t *next = LIST_NEXT(*ctx.first, vmm_region_t, node);

        pmap_move(vmm, ctx.first->head, dest_vmm, ctx.first->head + offset, ctx.first->tail - ctx.first->head + 1);

        ctx.first->vmm = dest_vmm;
        ctx.first->head += offset;
        ctx.first->tail += offset;

        dst_prev = merge_or_insert(dest_vmm, dst_prev, get_next(dest_vmm, dst_prev), ctx.first);

        if (ctx.first == ctx.last) break;
        ctx.first = next;
    }

    if (extra != 0) {
        memset(extra_region, 0, sizeof(*extra_region));
        extra_region->vmm = dest_vmm;
        extra_region->head = dest_addr + size;
        extra_region->tail = dest_tail;

        merge_or_insert(dest_vmm, dst_prev, get_next(dest_vmm, dst_prev), extra_region);
    }

ret:
    if (vmm == dest_vmm) {
        rmutex_rel(&vmm->lock);
    } else if ((uintptr_t)vmm < (uintptr_t)dest_vmm) {
        rmutex_rel(&dest_vmm->lock);
        rmutex_rel(&vmm->lock);
    } else {
        rmutex_rel(&vmm->lock);
        rmutex_rel(&dest_vmm->lock);
    }

    return RET_MAYBE(integer, error, dest_addr);
}

int vmm_unmap(vmm_t *vmm, uintptr_t address, size_t size) {
    if (unlikely(((address | size) & PAGE_MASK) != 0)) return EINVAL;
    if (unlikely(size == 0)) return EINVAL;

    uintptr_t tail = address + (size - 1);
    if (unlikely(address > tail)) tail = UINTPTR_MAX;

    rmutex_acq(&vmm->lock, 0, false);

    vmm_region_t *prev, *next;
    get_nonoverlap_bounds(vmm, address, tail, &prev, &next);

    int error = remove_overlapping_regions(vmm, &prev, &next, address, tail, false);
    rmutex_rel(&vmm->lock);
    return error;
}

vmm_region_t *vmm_get_region(vmm_t *vmm, uintptr_t address) {
    vmm_region_t *cur = vmm->regtree;

    for (;;) {
        if (unlikely(cur == NULL)) return NULL;
        if (cur->head <= address && address <= cur->tail) return cur;
        cur = address < cur->head ? cur->left : cur->right;
    }
}

void mem_object_init(mem_object_t *object) {
    static uint64_t next_id = 1;

    obj_init(&object->base, OBJECT_MEMORY);
    object->id = __atomic_fetch_add(&next_id, 1, __ATOMIC_RELAXED);
}

// These functions copy the data twice, because the actual read/write to/from the object data
// needs to be within an RCU critical section, and user_memcpy might page fault and sleep.

#define BUFFER_SIZE 1024

int mem_object_read(mem_object_t *object, void *buffer, size_t count, uint64_t position) {
    if (unlikely(count == 0)) return 0;

    const mem_object_ops_t *ops = (const mem_object_ops_t *)object->base.ops;
    if (unlikely(!ops->get_page)) return ENXIO;

    unsigned char buf[BUFFER_SIZE];

    do {
        size_t offset = position & PAGE_MASK;
        size_t current = PAGE_SIZE - offset;
        if (current > count) current = count;
        if (current > sizeof(buf)) current = sizeof(buf);

        rcu_state_t state;
        hydrogen_ret_t ret = ops->get_page(object, NULL, position >> PAGE_SHIFT, &state, false);
        if (unlikely(ret.error)) return ret.error;
        page_t *page = ret.pointer;
        memcpy(buf, page_to_virt(page) + offset, current);
        rcu_read_unlock(state);

        int error = user_memcpy(buffer, buf, current);
        if (unlikely(error)) return error;

        buffer += current;
        position += current;
        count -= current;
    } while (count != 0);

    return 0;
}

int mem_object_write(mem_object_t *object, const void *buffer, size_t count, uint64_t position) {
    if (unlikely(count == 0)) return 0;

    const mem_object_ops_t *ops = (const mem_object_ops_t *)object->base.ops;
    if (unlikely(!ops->get_page)) return ENXIO;

    unsigned char buf[BUFFER_SIZE];

    do {
        size_t offset = position & PAGE_MASK;
        size_t current = PAGE_SIZE - offset;
        if (current > count) current = count;
        if (current > sizeof(buf)) current = sizeof(buf);

        int error = user_memcpy(buf, buffer, current);
        if (unlikely(error)) return error;

        rcu_state_t state;
        hydrogen_ret_t ret = ops->get_page(object, NULL, position >> PAGE_SHIFT, &state, true);
        if (unlikely(ret.error)) return ret.error;
        page_t *page = ret.pointer;
        memcpy(page_to_virt(page) + offset, buf, current);
        rcu_read_unlock(state);

        buffer += current;
        position += current;
        count -= current;
    } while (count != 0);

    return 0;
}
