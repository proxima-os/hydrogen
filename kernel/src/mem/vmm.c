#include "mem/vmm.h"
#include "asm/irq.h"
#include "cpu/cpu.h"
#include "hydrogen/error.h"
#include "hydrogen/handle.h"
#include "hydrogen/memory.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/kmalloc.h"
#include "mem/obj/pmem.h"
#include "mem/pmap.h"
#include "mem/pmm.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "thread/mutex.h"
#include "util/handle.h"
#include "util/object.h"
#include "util/panic.h"
#include <stdint.h>

const size_t hydrogen_page_size = PAGE_SIZE;

static void replace_child(address_space_t *space, vm_region_t *parent, vm_region_t *from, vm_region_t *to) {
    to->parent = parent;

    if (parent) {
        if (parent->left == from) {
            parent->left = to;
        } else {
            parent->right = to;
        }
    } else {
        space->regtree = to;
    }
}

static vm_region_t *rotate_left(address_space_t *space, vm_region_t *root, vm_region_t *right) {
    vm_region_t *parent = root->parent;

    vm_region_t *new_right = right->left;
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

    replace_child(space, parent, root, right);
    return right;
}

static vm_region_t *rotate_right(address_space_t *space, vm_region_t *root, vm_region_t *left) {
    vm_region_t *parent = root->parent;

    vm_region_t *new_left = left->right;
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

    replace_child(space, parent, root, left);
    return left;
}

static vm_region_t *rotate_left_right(address_space_t *space, vm_region_t *root, vm_region_t *left) {
    vm_region_t *parent = root->parent;
    vm_region_t *new_root = left->right;

    vm_region_t *new_left_right = new_root->left;
    left->right = new_left_right;
    if (new_left_right) new_left_right->parent = left;

    new_root->left = left;
    left->parent = new_root;

    vm_region_t *new_right_left = new_root->right;
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
    replace_child(space, parent, root, new_root);
    return new_root;
}

static vm_region_t *rotate_right_left(address_space_t *space, vm_region_t *root, vm_region_t *right) {
    vm_region_t *parent = root->parent;
    vm_region_t *new_root = right->left;

    vm_region_t *new_right_left = new_root->right;
    right->left = new_right_left;
    if (new_right_left) new_right_left->parent = right;

    new_root->right = right;
    right->parent = new_root;

    vm_region_t *new_left_right = new_root->left;
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
    replace_child(space, parent, root, new_root);
    return new_root;
}

static void tree_add(address_space_t *space, vm_region_t *region) {
    vm_region_t *parent = NULL;
    vm_region_t **field = &space->regtree;
    vm_region_t *cur = *field;

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
                    parent = rotate_left_right(space, parent, region);
                } else {
                    parent = rotate_right(space, parent, region);
                }
            }
        } else {
            parent->balance += 1;

            if (parent->balance == 2) {
                if (region->balance < 0) {
                    parent = rotate_right_left(space, parent, region);
                } else {
                    parent = rotate_left(space, parent, region);
                }
            }
        }

        if (parent->balance == 0) break;

        region = parent;
        parent = parent->parent;
    }
}

static void tree_del(address_space_t *space, vm_region_t *region) {
retry: {
    vm_region_t *parent = region->parent;
    vm_region_t **field;

    if (parent) {
        if (region == parent->left) field = &parent->left;
        else field = &parent->right;
    } else {
        field = &space->regtree;
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
        vm_region_t *successor = region->right;
        while (successor->left) successor = successor->left;

        vm_region_t *orig_right = successor->right;
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

        goto retry;
    }

    // rebalance tree

    while (parent != NULL) {
        if (field == &parent->left) {
            parent->balance += 1;

            if (parent->balance == 2) {
                vm_region_t *right = parent->right;

                if (right->balance < 0) {
                    parent = rotate_right_left(space, parent, right);
                } else {
                    parent = rotate_left(space, parent, right);
                }
            }
        } else {
            parent->balance -= 1;

            if (parent->balance == -2) {
                vm_region_t *left = parent->left;

                if (left->balance > 0) {
                    parent = rotate_left_right(space, parent, left);
                } else {
                    parent = rotate_right(space, parent, left);
                }
            }
        }

        if (parent->balance != 0) break;

        parent = parent->parent;
    }
}
}

static bool is_tree_location_valid(vm_region_t *region, uintptr_t new_head) {
    if (region->parent) {
        if (region == region->parent->left) {
            if (new_head > region->parent->head) return false;
        } else if (new_head <= region->parent->head) {
            return false;
        }
    }

    if (region->left && new_head < region->left->head) return false;
    if (region->right && new_head >= region->right->head) return false;

    return true;
}

static void tree_mov(address_space_t *space, vm_region_t *region, uintptr_t new_head) {
    if (!is_tree_location_valid(region, new_head)) {
        tree_del(space, region);
        region->head = new_head;
        tree_add(space, region);
    }
}

static void list_add(address_space_t *space, vm_region_t *prev, vm_region_t *next, vm_region_t *region) {
    region->prev = prev;
    region->next = next;

    if (prev) prev->next = region;
    else space->regions = region;

    if (next) next->prev = region;
}

static void list_del(address_space_t *space, vm_region_t *prev, vm_region_t *next) {
    if (prev) prev->next = next;
    else space->regions = next;

    if (next) next->prev = prev;
}

static void address_space_free(object_t *ptr) {
    address_space_t *space = (address_space_t *)ptr;

    pmap_destroy(&space->pmap);
    pmm_unreserve(space->num_reserved);

    vm_region_t *cur = space->regions;

    while (cur) {
        if (cur->object.object) {
            obj_deref(cur->object.object);
        }

        vm_region_t *next = cur->next;
        vmfree(cur, sizeof(*cur));
        cur = next;
    }

    vmfree(space, sizeof(*space));
}

static const object_ops_t address_space_ops = {.free = address_space_free};

static hydrogen_error_t do_create(address_space_t **out) {
    address_space_t *space = kmalloc(sizeof(*space));
    if (unlikely(!space)) return HYDROGEN_OUT_OF_MEMORY;
    memset(space, 0, sizeof(*space));
    obj_init(&space->base, &address_space_ops);

    hydrogen_error_t error = pmap_create(&space->pmap);
    if (unlikely(error)) {
        vmfree(space, sizeof(*space));
        return error;
    }

    *out = space;
    return HYDROGEN_SUCCESS;
}

hydrogen_error_t hydrogen_vm_create(hydrogen_handle_t *vm) {
    address_space_t *space;
    hydrogen_error_t error = do_create(&space);
    if (unlikely(error)) return error;

    error = create_handle(&space->base, -1, vm);
    obj_deref(&space->base);
    return HYDROGEN_SUCCESS;
}

static bool is_address_space(object_t *obj) {
    return obj->ops == &address_space_ops;
}

static bool is_vm_object(object_t *obj) {
    return obj->ops == &pmem_vm_object_ops.base;
}

static hydrogen_error_t get_vm(hydrogen_handle_t handle, address_space_t **out, uint64_t rights) {
    if (handle) {
        handle_data_t data;
        hydrogen_error_t error = resolve(handle, &data, is_address_space, rights);
        if (unlikely(error)) return error;
        *out = (address_space_t *)data.object;
    } else {
        *out = current_thread->address_space;
    }

    return HYDROGEN_SUCCESS;
}

hydrogen_error_t clone_region(vm_region_t **out, address_space_t *space, vm_region_t *src) {
    hydrogen_error_t error = pmap_prepare(&space->pmap, src->head, src->tail - src->head + 1);
    if (unlikely(error)) return error;

    vm_region_t *dst = vmalloc(sizeof(*dst));
    if (unlikely(!dst)) return HYDROGEN_OUT_OF_MEMORY;
    memset(dst, 0, sizeof(*dst));

    dst->space = space;
    dst->head = src->head;
    dst->tail = src->tail;
    dst->flags = src->flags;
    dst->object = src->object;
    dst->offset = src->offset;

    if (dst->object.object) {
        obj_ref(dst->object.object);
    }

    *out = dst;
    return HYDROGEN_SUCCESS;
}

static hydrogen_error_t clone_regions(address_space_t *dst, address_space_t *src) {
    vm_region_t *scur = src->regtree;
    if (!scur) return HYDROGEN_SUCCESS;

    vm_region_t *dcur = NULL;
    int prev_relation = 0; // -1 = ascended from left subtree, 0 = descended, 1 = ascended from right subtree

    vm_region_t *last = NULL;

    for (;;) {
        // get or create dcur
        if (prev_relation == 0) {
            vm_region_t *dreg;
            hydrogen_error_t error = clone_region(&dreg, dst, scur);
            if (unlikely(error)) return error;

            dreg->balance = scur->balance;

            if (dcur) {
                dreg->parent = dcur;

                if (dreg->head < dcur->head) {
                    dcur->left = dreg;
                } else {
                    dcur->right = dreg;
                }
            } else {
                dst->regtree = dreg;
            }

            dcur = dreg;
        } else {
            dcur = dcur->parent;
        }

        // add to the region list if ascended from left subtree or descended into the leftmost node of its subtree
        if (prev_relation < 0 || (prev_relation == 0 && !scur->left)) {
            list_add(dst, last, NULL, dcur);
            last = dcur;
        }

        // traverse
        if (prev_relation == 0 && scur->left) {
            scur = scur->left;
            continue;
        }

        if (prev_relation <= 0 && scur->right) {
            scur = scur->right;
            prev_relation = 0;
            continue;
        }

        if (scur->parent) {
            if (scur == scur->parent->left) prev_relation = -1;
            else prev_relation = 1;

            scur = scur->parent;
            continue;
        }

        break;
    }

    return HYDROGEN_SUCCESS;
}

static void clone_pmap(address_space_t *dst, address_space_t *src) {
    for (vm_region_t *reg = dst->regions; reg != NULL; reg = reg->next) {
        pmap_clone(&dst->pmap, &src->pmap, reg->head, reg->tail - reg->head + 1, !(reg->flags & HYDROGEN_MEM_SHARED));
    }
}

hydrogen_error_t hydrogen_vm_clone(hydrogen_handle_t *vm, hydrogen_handle_t srch) {
    address_space_t *src;
    hydrogen_error_t error = get_vm(srch, &src, HYDROGEN_VM_RIGHT_CLONE);
    if (unlikely(error)) return error;

    address_space_t *dst;
    error = do_create(&dst);
    if (unlikely(error)) {
        if (srch) obj_deref(&src->base);
        return error;
    }

    mutex_lock(&src->lock);

    if (!pmm_reserve(src->num_reserved)) {
        mutex_unlock(&src->lock);
        obj_deref(&dst->base);
        if (srch) obj_deref(&src->base);
        return error;
    }

    dst->num_mapped = src->num_mapped;
    dst->num_reserved = src->num_reserved;

    error = clone_regions(dst, src);
    if (unlikely(error)) {
        mutex_unlock(&src->lock);
        obj_deref(&dst->base);
        if (srch) obj_deref(&src->base);
        return error;
    }

    clone_pmap(dst, src);

    mutex_unlock(&src->lock);
    if (srch) obj_deref(&src->base);

    error = create_handle(&dst->base, -1, vm);
    obj_deref(&dst->base);
    return error;
}

void vm_switch(address_space_t *space) {
    address_space_t *old = current_thread->address_space;
    current_thread->address_space = space;

    irq_state_t state = save_disable_irq();
    pmap_switch(space ? &space->pmap : NULL);
    restore_irq(state);

    if (space) obj_ref(&space->base);
    if (old) obj_deref(&old->base);
}

static void get_nonoverlap_bounds(
        address_space_t *space,
        uintptr_t head,
        uintptr_t tail,
        vm_region_t **prev_out,
        vm_region_t **next_out
) {
    vm_region_t *prev = NULL;
    vm_region_t *next = space->regions;

    while (next && next->tail < head) {
        prev = next;
        next = next->next;
    }

    while (next && next->head <= tail) {
        next = next->next;
    }

    *prev_out = prev;
    *next_out = next;
}

static vm_region_t *get_next(address_space_t *space, vm_region_t *prev) {
    return prev ? prev->next : space->regions;
}

#define SHARED_WRITE (HYDROGEN_MEM_SHARED | HYDROGEN_MEM_WRITE)

static bool need_manual_reserve(hydrogen_mem_flags_t flags, vm_object_t *obj) {
    if (!(flags & VM_PERM_MASK)) return false;
    if (!(flags & HYDROGEN_MEM_SHARED)) return true;

    return obj == NULL;
}

static void process_unmap(address_space_t *space, vm_region_t *region, uintptr_t head, uintptr_t tail) {
    size_t pages = (tail - head + 1) >> PAGE_SHIFT;

    pmap_unmap(&space->pmap, head, tail - head + 1);

    if (need_manual_reserve(region->flags, (vm_object_t *)region->object.object)) {
        pmm_unreserve(pages);
        space->num_reserved -= pages;
    }

    space->num_mapped -= pages;
}

static hydrogen_error_t remove_overlapping_regions(
        address_space_t *space,
        vm_region_t **prev_inout,
        vm_region_t **next_inout,
        uintptr_t head,
        uintptr_t tail
) {
    vm_region_t *prev = *prev_inout;
    vm_region_t *next = *next_inout;

    vm_region_t *cur = get_next(space, prev);

    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        if (cur->head < head && cur->tail > tail) {
            // Needs to be split into two
            // This is the *ONLY* branch allowed to return an error, because if this branch is taken it's the only
            // action done by the function, so there's no cleanup required on errors.
            ASSERT(cur->prev == prev);
            ASSERT(cur->next == next);
            process_unmap(space, cur, head, tail);

            vm_region_t *nreg = vmalloc(sizeof(*nreg));
            if (unlikely(!nreg)) return HYDROGEN_OUT_OF_MEMORY;
            memset(nreg, 0, sizeof(*nreg));

            nreg->space = space;
            nreg->head = tail + 1;
            nreg->tail = cur->tail;
            nreg->flags = cur->flags;
            nreg->object = cur->object;
            nreg->offset = cur->offset + (nreg->head - cur->head);
            if (cur->object.object) obj_ref(cur->object.object);

            cur->tail = head - 1;
            tree_add(space, nreg);
            list_add(space, cur, next, nreg);

            *prev_inout = cur;
            *next_inout = nreg;
            return HYDROGEN_SUCCESS;
        } else if (cur->head < head) {
            // Needs to be truncated
            ASSERT(cur->prev == prev);
            process_unmap(space, cur, head, cur->tail);

            cur->tail = head - 1;

            *prev_inout = cur;
            cur = cur->next;
        } else if (cur->tail > tail) {
            // Needs to be truncated and moved
            ASSERT(cur->next == next);
            process_unmap(space, cur, tail + 1, cur->tail);

            tree_mov(space, cur, tail + 1);

            *next_inout = cur;
            return HYDROGEN_SUCCESS;
        } else {
            // Needs to be completely removed
            process_unmap(space, cur, cur->head, cur->tail);

            vm_region_t *n = cur->next;

            tree_del(space, cur);
            list_del(space, cur->prev, cur);

            if (cur->object.object) obj_deref(cur->object.object);
            vmfree(cur, sizeof(*cur));

            cur = n;
        }
    }

    return HYDROGEN_SUCCESS;
}

static bool can_merge(vm_region_t *r1, vm_region_t *r2) {
    if (!r1 || !r2) return false;
    ASSERT(r1->head < r2->head);

    if (r1->tail + 1 != r2->head) return false;
    if (r1->flags != r2->flags) return false;
    if (r1->object.object != r2->object.object) return false;
    if (r1->object.rights != r2->object.rights) return false;
    if (r1->object.object && r1->offset + (r2->head - r1->head) != r2->offset) return false;

    return true;
}

// might free `region`
static void merge_or_insert(address_space_t *space, vm_region_t *prev, vm_region_t *next, vm_region_t *region) {
    bool prev_merge = can_merge(prev, region);
    bool next_merge = can_merge(region, next);

    if (prev_merge && next_merge) {
        prev->tail = next->tail;

        tree_del(space, next);
        list_del(space, prev, next->next);

        if (prev->object.object) {
            // both can merge with prev, so prev->object == region->object == next->object
            obj_deref(prev->object.object);
            obj_deref(prev->object.object);
        }

        vmfree(region, sizeof(*region));
        vmfree(next, sizeof(*next));
    } else if (prev_merge) {
        prev->tail = region->tail;

        if (prev->object.object) obj_deref(prev->object.object);
        vmfree(region, sizeof(*region));
    } else if (next_merge) {
        tree_mov(space, next, region->head);

        if (next->object.object) obj_deref(next->object.object);
        vmfree(region, sizeof(*region));
    } else {
        tree_add(space, region);
        list_add(space, prev, next, region);
    }
}

static hydrogen_error_t do_map(
        address_space_t *space,
        uintptr_t head,
        uintptr_t tail,
        hydrogen_mem_flags_t flags,
        handle_data_t *obj,
        size_t offset,
        vm_region_t *prev,
        vm_region_t *next
) {
    bool reserve = need_manual_reserve(flags, (vm_object_t *)obj->object);
    size_t pages = (tail - head + 1) >> PAGE_SHIFT;

    if (reserve && unlikely(!pmm_reserve(pages))) return HYDROGEN_OUT_OF_MEMORY;

    hydrogen_error_t error = pmap_prepare(&space->pmap, head, tail - head + 1);
    if (unlikely(error)) {
        if (reserve) pmm_unreserve(pages);
        return error;
    }

    vm_region_t *region = vmalloc(sizeof(*region));
    if (unlikely(!region)) return HYDROGEN_OUT_OF_MEMORY;
    memset(region, 0, sizeof(*region));

    region->space = space;
    region->head = head;
    region->tail = tail;
    region->flags = flags & VM_REGION_FLAG_MASK;
    region->object = *obj;
    region->offset = offset;

    error = remove_overlapping_regions(space, &prev, &next, head, tail);
    if (unlikely(error)) {
        vmfree(region, sizeof(*region));
        if (reserve) pmm_unreserve(pages);
        return error;
    }

    if (obj->object) obj_ref(obj->object);
    merge_or_insert(space, prev, next, region);

    space->num_mapped += pages;
    if (reserve) space->num_reserved += pages;

    if (obj->object) {
        vm_object_t *object = (vm_object_t *)obj->object;
        ((const vm_object_ops_t *)object->base.ops)->post_map(object, region);
    }

    return HYDROGEN_SUCCESS;
}

static uint64_t flags_to_rights(hydrogen_mem_flags_t flags) {
    uint64_t rights = 0;
    if (flags & HYDROGEN_MEM_READ) rights |= HYDROGEN_MEMORY_RIGHT_READ;
    if ((flags & SHARED_WRITE) == SHARED_WRITE) rights |= HYDROGEN_MEMORY_RIGHT_WRITE;
    if (flags & HYDROGEN_MEM_EXEC) rights |= HYDROGEN_MEMORY_RIGHT_EXEC;
    if (flags & VM_CACHE_MODE_MASK) rights |= HYDROGEN_MEMORY_RIGHT_CACHE;
    return rights;
}

static hydrogen_error_t do_map_exact(
        address_space_t *space,
        uintptr_t head,
        size_t size,
        hydrogen_mem_flags_t flags,
        handle_data_t *obj,
        size_t offset
) {
    uintptr_t tail = head + (size - 1);
    if (tail < head) return HYDROGEN_INVALID_ARGUMENT;
    if (head < PAGE_SIZE || tail >= max_user_address) return HYDROGEN_INVALID_ARGUMENT;

    vm_region_t *prev, *next;
    get_nonoverlap_bounds(space, head, tail, &prev, &next);

    if (!(flags & HYDROGEN_MEM_OVERWRITE) && get_next(space, prev) != next) return HYDROGEN_ALREADY_EXISTS;

    return do_map(space, head, tail, flags, obj, offset, prev, next);
}

static uintptr_t get_tail(vm_region_t *region) {
    return region ? region->tail : PAGE_MASK;
}

static uintptr_t get_head(vm_region_t *region) {
    return region ? region->head : max_user_address;
}

hydrogen_error_t hydrogen_vm_map(
        hydrogen_handle_t vm,
        uintptr_t *addr,
        size_t size,
        hydrogen_mem_flags_t flags,
        hydrogen_handle_t object,
        size_t offset
) {
    if (size == 0) return HYDROGEN_INVALID_ARGUMENT;

    uintptr_t wanted = *addr;
    if ((wanted | size | offset) & PAGE_MASK) return HYDROGEN_INVALID_ARGUMENT;
    if (flags & ~(VM_REGION_FLAG_MASK | VM_MAP_FLAG_MASK)) return HYDROGEN_INVALID_ARGUMENT;

    if ((flags & (HYDROGEN_MEM_OVERWRITE | HYDROGEN_MEM_EXACT)) == HYDROGEN_MEM_OVERWRITE) {
        return HYDROGEN_INVALID_ARGUMENT;
    }

    if (!object) {
        if (flags & (VM_CACHE_MODE_MASK | HYDROGEN_MEM_SHARED)) return HYDROGEN_INVALID_ARGUMENT;
    }

    address_space_t *space;
    handle_data_t obj;

    {
        uint64_t rights = HYDROGEN_VM_RIGHT_MAP;
        if (flags & HYDROGEN_MEM_OVERWRITE) rights |= HYDROGEN_VM_RIGHT_UNMAP;
        hydrogen_error_t error = get_vm(vm, &space, rights);
        if (unlikely(error)) return error;
    }

    if (object) {
        hydrogen_error_t error = resolve(object, &obj, is_vm_object, flags_to_rights(flags));
        if (unlikely(error)) {
            if (vm) obj_deref(&space->base);
            return error;
        }
    } else {
        obj = (handle_data_t){};
    }

    mutex_lock(&space->lock);

    hydrogen_error_t error = do_map_exact(space, wanted, size, flags, &obj, offset);
    if (!error || (flags & HYDROGEN_MEM_EXACT)) {
        mutex_unlock(&space->lock);
        if (object) obj_deref(obj.object);
        if (vm) obj_deref(&space->base);
        return error;
    }

    vm_region_t *prev = NULL;
    vm_region_t *next = space->regions;

    for (;;) {
        size_t avail = get_head(next) - get_tail(prev) + 1;
        if (avail >= size) break;

        if (!next) {
            mutex_unlock(&space->lock);
            if (object) obj_deref(obj.object);
            if (vm) obj_deref(&space->base);
            return HYDROGEN_OUT_OF_MEMORY;
        }

        prev = next;
        next = next->next;
    }

    uintptr_t head = get_tail(prev) + 1;
    uintptr_t tail = head + (size - 1);

    error = do_map(space, head, tail, flags, &obj, offset, prev, next);
    mutex_unlock(&space->lock);
    if (object) obj_deref(obj.object);
    if (vm) obj_deref(&space->base);

    if (likely(!error)) *addr = head;
    return error;
}

static hydrogen_error_t do_remap(
        address_space_t *space,
        vm_region_t *prev,
        vm_region_t *next,
        uintptr_t head,
        uintptr_t tail,
        hydrogen_mem_flags_t flags
) {
    vm_region_t *cur = get_next(space, prev);
    size_t extra_regions = 0;
    size_t num_unreserve = 0;
    size_t extra_reserve = 0;

    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        hydrogen_mem_flags_t new_flags = (cur->flags & ~VM_PERM_MASK) | flags;
        if (new_flags == cur->flags) {
            cur = cur->next;
            continue;
        }

        uintptr_t rhead = cur->head;
        uintptr_t rtail = cur->tail;

        if (cur->head < head) {
            rhead = head;
            extra_regions += 1;
        }

        if (cur->tail > tail) {
            rtail = tail;
            extra_regions += 1;
        }

        size_t pages = (rtail - rhead + 1) >> PAGE_SHIFT;

        if (cur->object.object) {
            uint64_t rights = flags_to_rights(new_flags);

            if ((cur->object.rights & rights) != rights) {
                if (extra_reserve) pmm_unreserve(extra_reserve);
                return HYDROGEN_NO_PERMISSION;
            }
        }

        bool was_reserved = need_manual_reserve(cur->flags, (vm_object_t *)cur->object.object);
        bool now_reserved = need_manual_reserve(new_flags, (vm_object_t *)cur->object.object);

        if (was_reserved) {
            if (!now_reserved) num_unreserve += pages;
        } else if (now_reserved) {
            if (unlikely(!pmm_reserve(pages))) {
                if (extra_reserve) pmm_unreserve(extra_reserve);
                return HYDROGEN_OUT_OF_MEMORY;
            }

            extra_reserve += pages;
        }

        bool was_mapped = cur->flags & VM_PERM_MASK;
        bool now_mapped = new_flags & VM_PERM_MASK;

        if (!was_mapped && now_mapped) {
            hydrogen_error_t error = pmap_prepare(&space->pmap, rhead, rtail - rhead + 1);
            if (unlikely(error)) {
                if (extra_reserve) pmm_unreserve(extra_reserve);
                return HYDROGEN_OUT_OF_MEMORY;
            }
        }
    }

    ASSERT(extra_regions <= 2);
    vm_region_t *regions = vmalloc(sizeof(*regions) * 2);
    if (unlikely(!regions)) {
        if (extra_reserve) pmm_unreserve(extra_reserve);
        return HYDROGEN_OUT_OF_MEMORY;
    }
    memset(regions, 0, sizeof(*regions) * 2);

    cur = get_next(space, prev);

    // No errors allowed from now on

    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        hydrogen_mem_flags_t new_flags = (cur->flags & ~VM_PERM_MASK) | flags;
        if (new_flags == cur->flags) {
            cur = cur->next;
            continue;
        }

        vm_region_t *region;

        if (cur->head < head && cur->tail > tail) {
            // Needs to be split into three
            ASSERT(extra_regions >= 2);
            ASSERT(cur->prev == prev);
            ASSERT(cur->next == next);

            regions[0].space = space;
            regions[0].head = head;
            regions[0].tail = tail;
            regions[0].flags = cur->flags;
            regions[0].object = cur->object;
            regions[0].offset = cur->offset + (head - cur->head);

            regions[1].space = space;
            regions[1].head = tail + 1;
            regions[1].tail = cur->tail;
            regions[1].flags = cur->flags;
            regions[1].object = cur->object;
            regions[1].offset = cur->offset + (tail + 1 - cur->head);

            if (cur->object.object) {
                obj_ref(cur->object.object);
                obj_ref(cur->object.object);
            }

            cur->tail = head - 1;
            tree_add(space, &regions[0]);
            tree_add(space, &regions[1]);
            list_add(space, cur, next, &regions[0]);
            list_add(space, &regions[0], next, &regions[1]);

            region = &regions[0];
            cur = &regions[1];

            regions += 2;
            extra_regions -= 2;
        } else if (cur->head < head) {
            // Needs to be split into two
            ASSERT(extra_regions >= 1);
            ASSERT(cur->prev == prev);

            region = regions++;
            extra_regions--;

            region->space = space;
            region->head = head;
            region->tail = cur->tail;
            region->flags = cur->flags;
            region->object = cur->object;
            region->offset = cur->offset + (head - cur->head);

            if (cur->object.object) {
                obj_ref(cur->object.object);
            }

            cur->tail = head - 1;
            tree_add(space, region);
            list_add(space, cur, cur->next, region);
        } else if (cur->tail > tail) {
            // Needs to be split into two
            ASSERT(extra_regions >= 1);
            ASSERT(cur->next == next);

            region = cur;
            cur = regions++;
            extra_regions--;

            cur->space = space;
            cur->head = tail + 1;
            cur->tail = region->tail;
            cur->flags = region->flags;
            cur->object = region->object;
            cur->offset = region->offset + (cur->head - region->head);

            if (cur->object.object) {
                obj_ref(cur->object.object);
            }

            region->tail = tail;
            tree_add(space, cur);
            list_add(space, region, region->next, cur);
        } else {
            region = cur;
        }

        region->flags = new_flags;

        if (new_flags & VM_PERM_MASK) {
            pmap_remap(&space->pmap, region->head, region->tail - region->head + 1, region->flags);
        } else {
            pmap_unmap(&space->pmap, region->head, region->tail - region->head + 1);
        }

        cur = cur->next;
    }

    space->num_reserved += extra_reserve;
    space->num_reserved -= num_unreserve;

    if (num_unreserve) {
        pmm_unreserve(num_unreserve);
    }

    return HYDROGEN_SUCCESS;
}

hydrogen_error_t hydrogen_vm_remap(hydrogen_handle_t vm, uintptr_t addr, size_t size, hydrogen_mem_flags_t flags) {
    if (size == 0) return HYDROGEN_INVALID_ARGUMENT;
    if ((addr | size) & PAGE_MASK) return HYDROGEN_INVALID_ARGUMENT;
    if (flags & ~VM_PERM_MASK) return HYDROGEN_INVALID_ARGUMENT;

    uintptr_t tail = addr + (size - 1);
    if (tail < addr) return HYDROGEN_INVALID_ARGUMENT;
    if (addr < PAGE_SIZE || tail >= max_user_address) return HYDROGEN_INVALID_ARGUMENT;

    address_space_t *space;
    hydrogen_error_t error = get_vm(vm, &space, HYDROGEN_VM_RIGHT_REMAP);
    if (unlikely(error)) return error;

    mutex_lock(&space->lock);

    vm_region_t *prev, *next;
    get_nonoverlap_bounds(space, addr, tail, &prev, &next);

    error = do_remap(space, prev, next, addr, tail, flags);
    mutex_unlock(&space->lock);
    if (vm) obj_deref(&space->base);
    return error;
}

hydrogen_error_t hydrogen_vm_unmap(hydrogen_handle_t vm, uintptr_t addr, size_t size) {
    if (size == 0) return HYDROGEN_INVALID_ARGUMENT;
    if ((addr | size) & PAGE_MASK) return HYDROGEN_INVALID_ARGUMENT;

    uintptr_t tail = addr + (size - 1);
    if (tail < addr) return HYDROGEN_INVALID_ARGUMENT;
    if (addr < PAGE_SIZE || tail >= max_user_address) return HYDROGEN_INVALID_ARGUMENT;

    address_space_t *space;
    hydrogen_error_t error = get_vm(vm, &space, HYDROGEN_VM_RIGHT_REMAP);
    if (unlikely(error)) return error;

    mutex_lock(&space->lock);

    vm_region_t *prev, *next;
    get_nonoverlap_bounds(space, addr, tail, &prev, &next);

    error = remove_overlapping_regions(space, &prev, &next, addr, tail);
    mutex_unlock(&space->lock);
    if (vm) obj_deref(&space->base);
    return error;
}

void vm_obj_init(vm_object_t *obj, const vm_object_ops_t *ops) {
    obj_init(&obj->base, &ops->base);
}

vm_region_t *vm_get_region(address_space_t *space, uintptr_t address) {
    vm_region_t *cur = space->regtree;

    while (cur && (address < cur->head || address > cur->tail)) {
        if (address < cur->head) cur = cur->left;
        else cur = cur->right;
    }

    return cur;
}
