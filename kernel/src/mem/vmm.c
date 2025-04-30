#include "mem/vmm.h"
#include "asm/irq.h"
#include "cpu/cpu.h"
#include "errno.h"
#include "hydrogen/memory.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "kernel/return.h"
#include "mem/kmalloc.h"
#include "mem/obj/pmem.h"
#include "mem/pmap.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "sys/syscall.h"
#include "sys/usermem.h"
#include "sys/vdso.h"
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

        *field = successor;
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
    } else {
        region->head = new_head;
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

    vm_region_t *cur = space->regions;

    while (cur) {
        if (cur->object.object) {
            obj_deref(cur->object.object);
        }

        vm_region_t *next = cur->next;
        kfree(cur, sizeof(*cur));
        cur = next;
    }

    vmfree(space, sizeof(*space));
}

static const object_ops_t address_space_ops = {.free = address_space_free};

static int do_create(address_space_t **out) {
    address_space_t *space = vmalloc(sizeof(*space));
    if (unlikely(!space)) return ENOMEM;
    memset(space, 0, sizeof(*space));
    obj_init(&space->base, &address_space_ops);
    pmap_create(&space->pmap);

    *out = space;
    return 0;
}

hydrogen_ret_t hydrogen_vm_create(void) {
    address_space_t *space;
    int error = do_create(&space);
    if (unlikely(error)) return RET_ERROR(error);

    hydrogen_handle_t handle;
    error = create_handle(&space->base, -1, &handle);
    obj_deref(&space->base);
    return RET_HANDLE_MAYBE(error, handle);
}

static bool is_address_space(object_t *obj) {
    return obj->ops == &address_space_ops;
}

static bool is_vm_object(object_t *obj) {
    return obj->ops == &pmem_vm_object_ops.base;
}

int get_vm(hydrogen_handle_t handle, address_space_t **out, uint64_t rights) {
    if (handle) {
        handle_data_t data;
        int error = resolve(handle, &data, is_address_space, rights);
        if (unlikely(error)) return error;
        *out = (address_space_t *)data.object;
    } else {
        *out = current_thread->address_space;
    }

    return 0;
}

vm_region_t *clone_region(address_space_t *dspace, address_space_t *sspace, vm_region_t *src) {
    vm_region_t *dst = kmalloc(sizeof(*dst));
    memset(dst, 0, sizeof(*dst));

    dst->space = dspace;
    dst->head = src->head;
    dst->tail = src->tail;
    dst->flags = src->flags;
    dst->object = src->object;
    dst->offset = src->offset;

    if (dst->object.object) {
        obj_ref(dst->object.object);
    }

    pmap_clone(&dspace->pmap, &sspace->pmap, dst->head, dst->tail - dst->head + 1, !(dst->flags & HYDROGEN_MEM_SHARED));

    return dst;
}

static void clone_regions(address_space_t *dst, address_space_t *src) {
    vm_region_t *scur = src->regtree;
    if (!scur) return;

    vm_region_t *dcur = NULL;
    int prev_relation = 0; // -1 = ascended from left subtree, 0 = descended, 1 = ascended from right subtree

    vm_region_t *last = NULL;

    for (;;) {
        // get or create dcur
        if (prev_relation == 0) {
            vm_region_t *dreg = clone_region(dst, src, scur);

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
}

hydrogen_ret_t hydrogen_vm_clone(hydrogen_handle_t srch) {
    address_space_t *src;
    int error = get_vm(srch, &src, HYDROGEN_VM_RIGHT_CLONE);
    if (unlikely(error)) return RET_ERROR(error);

    address_space_t *dst;
    error = do_create(&dst);
    if (unlikely(error)) {
        if (srch) obj_deref(&src->base);
        return RET_ERROR(error);
    }

    mutex_lock(&src->lock);

    dst->num_mapped = src->num_mapped;
    dst->vdso_addr = src->vdso_addr;

    clone_regions(dst, src);

    mutex_unlock(&src->lock);
    if (srch) obj_deref(&src->base);

    hydrogen_handle_t handle;
    error = create_handle(&dst->base, -1, &handle);
    obj_deref(&dst->base);
    return RET_HANDLE_MAYBE(error, handle);
}

void vm_switch(address_space_t *space) {
    address_space_t *old = current_thread->address_space;
    current_thread->address_space = space;

    mutex_lock(&space->lock);
    // The vDSO is not allowed to be mapped after the address space has already been used for anything.
    if (!space->vdso_addr) space->vdso_addr = UINTPTR_MAX - vdso_size;
    mutex_unlock(&space->lock);

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

static void process_unmap(address_space_t *space, uintptr_t head, uintptr_t tail) {
    size_t pages = (tail - head + 1) >> PAGE_SHIFT;

    pmap_unmap(&space->pmap, head, tail - head + 1);
    space->num_mapped -= pages;
}

static int remove_overlapping_regions(
        address_space_t *space,
        vm_region_t **prev_inout,
        vm_region_t **next_inout,
        uintptr_t head,
        uintptr_t tail
) {
    vm_region_t *prev = *prev_inout;
    vm_region_t *next = *next_inout;

    vm_region_t *cur = get_next(space, prev);

    // Do this in a separate iteration, otherwise cleanup becomes very complicated
    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        if (cur->object.object == vdso_handle.object) {
            return EACCES;
        }

        cur = cur->next;
    }

    cur = get_next(space, prev);

    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        if (cur->head < head && cur->tail > tail) {
            // Needs to be split into two
            ASSERT(cur->prev == prev);
            ASSERT(cur->next == next);
            process_unmap(space, head, tail);

            vm_region_t *nreg = kmalloc(sizeof(*nreg));
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
            return 0;
        } else if (cur->head < head) {
            // Needs to be truncated
            ASSERT(cur->prev == prev);
            process_unmap(space, head, cur->tail);

            cur->tail = head - 1;

            *prev_inout = cur;
            cur = cur->next;
        } else if (cur->tail > tail) {
            // Needs to be truncated and moved
            ASSERT(cur->next == next);
            process_unmap(space, cur->head, tail);

            tree_mov(space, cur, tail + 1);

            *next_inout = cur;
            return 0;
        } else {
            // Needs to be completely removed
            process_unmap(space, cur->head, cur->tail);

            vm_region_t *n = cur->next;

            tree_del(space, cur);
            list_del(space, cur->prev, n);

            if (cur->object.object) obj_deref(cur->object.object);
            kfree(cur, sizeof(*cur));

            cur = n;
        }
    }

    return 0;
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
static vm_region_t *merge_or_insert(address_space_t *space, vm_region_t *prev, vm_region_t *next, vm_region_t *region) {
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

        kfree(region, sizeof(*region));
        kfree(next, sizeof(*next));
        return prev;
    } else if (prev_merge) {
        prev->tail = region->tail;

        if (prev->object.object) obj_deref(prev->object.object);
        kfree(region, sizeof(*region));
        return prev;
    } else if (next_merge) {
        tree_mov(space, next, region->head);

        if (next->object.object) obj_deref(next->object.object);
        kfree(region, sizeof(*region));
        return next;
    } else {
        tree_add(space, region);
        list_add(space, prev, next, region);
        return region;
    }
}

static int do_map(
        address_space_t *space,
        uintptr_t head,
        uintptr_t tail,
        unsigned flags,
        handle_data_t *obj,
        size_t offset,
        vm_region_t *prev,
        vm_region_t *next
) {
    size_t pages = (tail - head + 1) >> PAGE_SHIFT;

    vm_region_t *region = kmalloc(sizeof(*region));
    memset(region, 0, sizeof(*region));

    region->space = space;
    region->head = head;
    region->tail = tail;
    region->flags = flags & VM_REGION_FLAG_MASK;
    region->object = *obj;
    region->offset = offset;

    int error = remove_overlapping_regions(space, &prev, &next, head, tail);
    if (unlikely(error)) {
        kfree(region, sizeof(*region));
        return error;
    }

    if (obj->object) obj_ref(obj->object);
    merge_or_insert(space, prev, next, region);

    space->num_mapped += pages;

    if (obj->object) {
        vm_object_t *object = (vm_object_t *)obj->object;
        ((const vm_object_ops_t *)object->base.ops)->post_map(object, region);
    }

    return 0;
}

static uint64_t flags_to_rights(unsigned flags) {
    uint64_t rights = 0;
    if (flags & HYDROGEN_MEM_READ) rights |= HYDROGEN_MEMORY_RIGHT_READ;
    if ((flags & SHARED_WRITE) == SHARED_WRITE) rights |= HYDROGEN_MEMORY_RIGHT_WRITE;
    if (flags & HYDROGEN_MEM_EXEC) rights |= HYDROGEN_MEMORY_RIGHT_EXEC;
    if (flags & VM_CACHE_MODE_MASK) rights |= HYDROGEN_MEMORY_RIGHT_CACHE;
    if (!(flags & HYDROGEN_MEM_SHARED)) rights |= HYDROGEN_MEMORY_RIGHT_PRIVATE;
    return rights;
}

static int do_map_exact(
        address_space_t *space,
        uintptr_t head,
        size_t size,
        unsigned flags,
        handle_data_t *obj,
        size_t offset
) {
    uintptr_t tail = head + (size - 1);
    if (tail < head) return EINVAL;
    if (head < PAGE_SIZE || tail >= max_user_address) return EINVAL;

    vm_region_t *prev, *next;
    get_nonoverlap_bounds(space, head, tail, &prev, &next);

    if (!(flags & HYDROGEN_MEM_OVERWRITE) && get_next(space, prev) != next) return EEXIST;

    return do_map(space, head, tail, flags, obj, offset, prev, next);
}

static uintptr_t get_tail(vm_region_t *region) {
    return region ? region->tail : PAGE_MASK;
}

static uintptr_t get_head(vm_region_t *region) {
    return region ? region->head : max_user_address;
}

static int find_map_location(
        address_space_t *space,
        size_t size,
        vm_region_t **prev_out,
        vm_region_t **next_out,
        uintptr_t *head_out,
        uintptr_t *tail_out
) {
    vm_region_t *prev = NULL;
    vm_region_t *next = space->regions;

    for (;;) {
        size_t avail = get_head(next) - get_tail(prev) + 1;
        if (avail >= size) break;

        if (!next) return ENOMEM;

        prev = next;
        next = next->next;
    }

    uintptr_t head = get_tail(prev) + 1;
    uintptr_t tail = head + (size - 1);

    *prev_out = prev;
    *next_out = next;
    *head_out = head;
    *tail_out = tail;

    return 0;
}

hydrogen_ret_t hydrogen_vm_map(
        hydrogen_handle_t vm,
        uintptr_t addr,
        size_t size,
        unsigned flags,
        hydrogen_handle_t object,
        size_t offset
) {
    if (size == 0) return RET_ERROR(EINVAL);

    if ((addr | size | offset) & PAGE_MASK) return RET_ERROR(EINVAL);
    if (flags & ~(VM_REGION_FLAG_MASK | VM_MAP_FLAG_MASK)) return RET_ERROR(EINVAL);

    if ((flags & (HYDROGEN_MEM_OVERWRITE | HYDROGEN_MEM_EXACT)) == HYDROGEN_MEM_OVERWRITE) {
        return RET_ERROR(EINVAL);
    }

    if (!object) {
        if (flags & VM_CACHE_MODE_MASK) return RET_ERROR(EINVAL);
    }

    address_space_t *space;
    handle_data_t obj;

    {
        uint64_t rights = HYDROGEN_VM_RIGHT_MAP;
        if (flags & HYDROGEN_MEM_OVERWRITE) rights |= HYDROGEN_VM_RIGHT_UNMAP;
        int error = get_vm(vm, &space, rights);
        if (unlikely(error)) return RET_ERROR(error);
    }

    if (object) {
        int error = resolve(object, &obj, is_vm_object, flags_to_rights(flags));
        if (unlikely(error)) {
            if (vm) obj_deref(&space->base);
            return RET_ERROR(error);
        }
    } else {
        obj = (handle_data_t){};
    }

    mutex_lock(&space->lock);

    int error = do_map_exact(space, addr, size, flags, &obj, offset);
    if (!error || (flags & HYDROGEN_MEM_EXACT)) {
        mutex_unlock(&space->lock);
        if (object) obj_deref(obj.object);
        if (vm) obj_deref(&space->base);
        return RET_POINTER_MAYBE(error, (void *)addr);
    }

    vm_region_t *prev, *next;
    uintptr_t head, tail;
    error = find_map_location(space, size, &prev, &next, &head, &tail);

    if (likely(!error)) {
        error = do_map(space, head, tail, flags, &obj, offset, prev, next);

        if (likely(!error)) {
            addr = head;
        }
    }

    mutex_unlock(&space->lock);
    if (object) obj_deref(obj.object);
    if (vm) obj_deref(&space->base);
    return RET_POINTER_MAYBE(error, (void *)addr);
}

hydrogen_ret_t hydrogen_vm_map_vdso(hydrogen_handle_t vm) {
    address_space_t *space;
    int error = get_vm(vm, &space, HYDROGEN_VM_RIGHT_MAP);
    if (unlikely(error)) return RET_ERROR(error);

    mutex_lock(&space->lock);

    if (space->vdso_addr) {
        mutex_unlock(&space->lock);
        if (vm) obj_deref(&space->base);
        return RET_ERROR(error);
    }

    vm_region_t *prev, *next;
    uintptr_t head, tail;
    error = find_map_location(space, vdso_size, &prev, &next, &head, &tail);

    if (likely(!error)) {
        error = do_map(
                space,
                head,
                tail,
                HYDROGEN_MEM_SHARED | HYDROGEN_MEM_EXEC | HYDROGEN_MEM_READ,
                &vdso_handle,
                0,
                prev,
                next
        );

        if (likely(!error)) {
            head += PAGE_SIZE;
            space->vdso_addr = head;
        }
    }

    mutex_unlock(&space->lock);
    if (vm) obj_deref(&space->base);
    return RET_POINTER_MAYBE(error, (void *)head);
}

static int split_to_exact(
        address_space_t *space,
        vm_region_t *prev,
        vm_region_t *next,
        uintptr_t head,
        uintptr_t tail,
        int (*check_cb)(vm_region_t *, void *), /* returns 1 if the region should be skipped. negative = error code */
        bool (*skip_cb)(vm_region_t *, void *), /* must return true if and only if check_cb returned 1 */
        void (*final_cb)(address_space_t *space, vm_region_t *, void *),
        void *ctx
) {
    vm_region_t *cur = get_next(space, prev);
    size_t extra_regions = 0;

    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        int ret = check_cb(cur, ctx);
        if (unlikely(ret < 0)) return -ret;

        if (likely(ret == 0)) {
            if (cur->head < head) extra_regions += 1;
            if (cur->tail > tail) extra_regions += 1;
        }

        cur = cur->next;
    }

    ASSERT(extra_regions <= 2);
    vm_region_t *regions[2];

    for (size_t i = 0; i < extra_regions; i++) {
        regions[i] = kmalloc(sizeof(*regions[i]));
        memset(regions[i], 0, sizeof(*regions[i]));
    }

    cur = get_next(space, prev);

    // No errors allowed from now on

    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        if (skip_cb(cur, ctx)) {
            cur = cur->next;
            continue;
        }

        vm_region_t *region;

        if (cur->head < head && cur->tail > tail) {
            // Needs to be split into three
            ASSERT(extra_regions >= 2);
            ASSERT(cur->prev == prev);
            ASSERT(cur->next == next);

            extra_regions -= 2;
            vm_region_t **new_regions = &regions[extra_regions];

            new_regions[0]->space = space;
            new_regions[0]->head = head;
            new_regions[0]->tail = tail;
            new_regions[0]->flags = cur->flags;
            new_regions[0]->object = cur->object;
            new_regions[0]->offset = cur->offset + (head - cur->head);

            new_regions[1]->space = space;
            new_regions[1]->head = tail + 1;
            new_regions[1]->tail = cur->tail;
            new_regions[1]->flags = cur->flags;
            new_regions[1]->object = cur->object;
            new_regions[1]->offset = cur->offset + (tail + 1 - cur->head);

            if (cur->object.object) {
                obj_ref(cur->object.object);
                obj_ref(cur->object.object);
            }

            cur->tail = head - 1;
            tree_add(space, new_regions[0]);
            tree_add(space, new_regions[1]);
            list_add(space, cur, next, new_regions[0]);
            list_add(space, new_regions[0], next, new_regions[1]);

            region = new_regions[0];
            cur = new_regions[1];
        } else if (cur->head < head) {
            // Needs to be split into two
            ASSERT(extra_regions >= 1);
            ASSERT(cur->prev == prev);

            region = regions[--extra_regions];

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
            cur = regions[--extra_regions];

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

        cur = cur->next;
        final_cb(space, region, ctx);
    }

    ASSERT(extra_regions == 0);
    return 0;
}

static int remap_check_cb(vm_region_t *region, void *ctx) {
    unsigned new_flags = (region->flags & ~VM_PERM_MASK) | (uintptr_t)ctx;
    if (new_flags == region->flags) return 1;
    if (region->object.object == vdso_handle.object) return -EACCES;

    if (region->object.object) {
        uint64_t rights = flags_to_rights(new_flags);

        if ((region->object.rights & rights) != rights) return -EACCES;
    }

    return 0;
}

static bool remap_skip_cb(vm_region_t *region, void *ctx) {
    unsigned new_flags = (region->flags & ~VM_PERM_MASK) | (uintptr_t)ctx;
    return new_flags == region->flags;
}

static void remap_final_cb(address_space_t *space, vm_region_t *region, void *ctx) {
    unsigned new_flags = (region->flags & ~VM_PERM_MASK) | (uintptr_t)ctx;
    region->flags = new_flags;

    if (new_flags & VM_PERM_MASK) {
        pmap_remap(&space->pmap, region->head, region->tail - region->head + 1, region->flags);
    } else {
        pmap_unmap(&space->pmap, region->head, region->tail - region->head + 1);
    }
}

static int do_remap(
        address_space_t *space,
        vm_region_t *prev,
        vm_region_t *next,
        uintptr_t head,
        uintptr_t tail,
        unsigned flags
) {
    return split_to_exact(
            space,
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

int hydrogen_vm_remap(hydrogen_handle_t vm, uintptr_t addr, size_t size, unsigned flags) {
    if (size == 0) return EINVAL;
    if ((addr | size) & PAGE_MASK) return EINVAL;
    if (flags & ~VM_PERM_MASK) return EINVAL;

    uintptr_t tail = addr + (size - 1);
    if (tail < addr) return EINVAL;
    if (addr < PAGE_SIZE || tail >= max_user_address) return EINVAL;

    address_space_t *space;
    int error = get_vm(vm, &space, HYDROGEN_VM_RIGHT_REMAP);
    if (unlikely(error)) return error;

    mutex_lock(&space->lock);

    vm_region_t *prev, *next;
    get_nonoverlap_bounds(space, addr, tail, &prev, &next);

    error = do_remap(space, prev, next, addr, tail, flags);
    mutex_unlock(&space->lock);
    if (vm) obj_deref(&space->base);
    return error;
}

struct move_ctx {
    vm_region_t *first;
    vm_region_t *last;
};

static int move_check_cb(vm_region_t *region, UNUSED void *ptr) {
    if (unlikely(region->object.object == vdso_handle.object)) return -EACCES;

    return 0;
}

static bool move_skip_cb(UNUSED vm_region_t *region, UNUSED void *ptr) {
    return false;
}

static void move_final_cb(address_space_t *space, vm_region_t *region, void *ptr) {
    struct move_ctx *ctx = ptr;

    tree_del(space, region);
    list_del(space, region->prev, region->next);

    if (!ctx->first) ctx->first = region;
    ctx->last = region;
}

hydrogen_ret_t hydrogen_vm_move(
        hydrogen_handle_t vm,
        uintptr_t addr,
        size_t size,
        hydrogen_handle_t dest_vm,
        uintptr_t dest_addr,
        size_t dest_size
) {
    if (unlikely(size == 0)) return RET_ERROR(EINVAL);
    if (unlikely(size > dest_size)) return RET_ERROR(EINVAL);
    if (unlikely((addr | dest_addr | size | dest_size) & PAGE_MASK)) return RET_ERROR(EINVAL);

    uintptr_t tail = addr + (size - 1);
    if (unlikely(tail < addr)) return RET_ERROR(EINVAL);
    if (unlikely(addr < PAGE_SIZE)) return RET_ERROR(EINVAL);
    if (unlikely(tail >= max_user_address)) return RET_ERROR(EINVAL);

    uintptr_t dest_tail;

    if (dest_addr != 0) {
        dest_tail = dest_addr + (dest_size - 1);
        if (unlikely(dest_tail < dest_addr)) return RET_ERROR(EINVAL);
        if (unlikely(dest_addr < PAGE_SIZE)) return RET_ERROR(EINVAL);
        if (unlikely(dest_tail >= max_user_address)) return RET_ERROR(EINVAL);
    }

    address_space_t *src;
    int error = get_vm(vm, &src, HYDROGEN_VM_RIGHT_UNMAP);
    if (unlikely(error)) return RET_ERROR(error);

    address_space_t *dst;
    error = get_vm(dest_vm, &dst, HYDROGEN_VM_RIGHT_MAP);
    if (unlikely(error)) {
        if (vm) obj_deref(&src->base);
        return RET_ERROR(error);
    }

    mutex_lock(&dst->lock);

    vm_region_t *dst_prev, *dst_next;

    if (dest_addr != 0) {
        get_nonoverlap_bounds(dst, dest_addr, dest_tail, &dst_prev, &dst_next);
        if (unlikely(get_next(dst, dst_prev) != dst_next)) {
            error = EEXIST;
            goto ret;
        }
    } else {
        error = find_map_location(dst, dest_size, &dst_prev, &dst_next, &dest_addr, &dest_tail);
        if (unlikely(error)) goto ret;
    }

    if (src != dst) mutex_lock(&src->lock);

    vm_region_t *prev, *next;
    get_nonoverlap_bounds(src, addr, tail, &prev, &next);

    struct move_ctx ctx = {};
    error = split_to_exact(src, prev, next, addr, tail, move_check_cb, move_skip_cb, move_final_cb, &ctx);
    if (unlikely(error)) goto ret2;

    // get bounds again since the pointers may have changed in split_to_exact
    get_nonoverlap_bounds(dst, dest_addr, dest_tail, &dst_prev, &dst_next);

    uintptr_t offset = dest_addr - addr;

    while (ctx.first) {
        vm_region_t *next = ctx.first->next;

        pmap_move(
                &src->pmap,
                &dst->pmap,
                ctx.first->head,
                ctx.first->head + offset,
                ctx.first->tail - ctx.first->head + 1
        );

        ctx.first->space = dst;
        ctx.first->head += offset;
        ctx.first->tail += offset;

        dst_prev = merge_or_insert(dst, dst_prev, get_next(dst, dst_prev), ctx.first);

        if (ctx.first == ctx.last) break;
        ctx.first = next;
    }

    if (size < dest_size) {
        vm_region_t *region = kmalloc(sizeof(*region));
        memset(region, 0, sizeof(*region));

        region->space = dst;
        region->head = dest_addr + size;
        region->tail = dest_tail;

        merge_or_insert(dst, dst_prev, get_next(dst, dst_prev), region);
    }

ret2:
    if (src != dst) mutex_unlock(&src->lock);
ret:
    mutex_unlock(&dst->lock);
    if (dest_vm) obj_deref(&dst->base);
    if (vm) obj_deref(&src->base);
    return RET_POINTER_MAYBE(error, (void *)dest_addr);
}

int hydrogen_vm_unmap(hydrogen_handle_t vm, uintptr_t addr, size_t size) {
    if (size == 0) return EINVAL;
    if ((addr | size) & PAGE_MASK) return EINVAL;

    uintptr_t tail = addr + (size - 1);
    if (tail < addr) return EINVAL;
    if (addr < PAGE_SIZE || tail >= max_user_address) return EINVAL;

    address_space_t *space;
    int error = get_vm(vm, &space, HYDROGEN_VM_RIGHT_REMAP);
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

int hydrogen_vm_write(hydrogen_handle_t vm, uintptr_t dest, const void *src, size_t size) {
    if (unlikely(size == 0)) return EINVAL;

    int error = verify_user_pointer(src, size);
    if (unlikely(error)) return error;

    error = verify_user_pointer((const void *)dest, size);
    if (unlikely(error)) return error;

    address_space_t *space;

    {
        handle_data_t data;
        error = resolve(vm, &data, is_address_space, HYDROGEN_VM_RIGHT_WRITE);
        if (unlikely(error)) return error;
        space = (address_space_t *)data.object;
        if (space == current_thread->address_space) {
            obj_deref(&space->base);
            return EINVAL;
        }
    }

    address_space_t *orig_space = current_thread->address_space;
    unsigned char buffer[1024];

    do {
        size_t cur = sizeof(buffer);
        if (cur > size) cur = size;

        error = memcpy_user(buffer, src, cur);
        if (unlikely(error)) break;

        irq_state_t state = save_disable_irq();
        current_thread->address_space = space;
        pmap_switch(&space->pmap);
        restore_irq(state);

        error = memcpy_user((void *)dest, buffer, cur);

        state = save_disable_irq();
        current_thread->address_space = orig_space;
        pmap_switch(orig_space ? &orig_space->pmap : NULL);
        restore_irq(state);

        if (unlikely(error)) break;

        dest += cur;
        src += cur;
        size -= cur;
    } while (size > 0);

    obj_deref(&space->base);
    return error;
}

int hydrogen_vm_fill(hydrogen_handle_t vm, uintptr_t dest, uint8_t value, size_t size) {
    if (unlikely(size == 0)) return EINVAL;

    int error = verify_user_pointer((const void *)dest, size);
    if (unlikely(error)) return error;

    address_space_t *space;

    {
        handle_data_t data;
        error = resolve(vm, &data, is_address_space, HYDROGEN_VM_RIGHT_WRITE);
        if (unlikely(error)) return error;
        space = (address_space_t *)data.object;
        if (space == current_thread->address_space) {
            obj_deref(&space->base);
            return EINVAL;
        }
    }

    address_space_t *orig_space = current_thread->address_space;

    irq_state_t state = save_disable_irq();
    current_thread->address_space = space;
    pmap_switch(&space->pmap);
    restore_irq(state);

    error = memset_user((void *)dest, value, size);

    state = save_disable_irq();
    current_thread->address_space = orig_space;
    pmap_switch(orig_space ? &orig_space->pmap : NULL);
    restore_irq(state);

    obj_deref(&space->base);
    return error;
}

int hydrogen_vm_read(hydrogen_handle_t vm, void *dest, uintptr_t src, size_t size) {
    if (unlikely(size == 0)) return EINVAL;

    int error = verify_user_pointer(dest, size);
    if (unlikely(error)) return error;

    error = verify_user_pointer((const void *)src, size);
    if (unlikely(error)) return error;

    address_space_t *space;

    {
        handle_data_t data;
        error = resolve(vm, &data, is_address_space, HYDROGEN_VM_RIGHT_READ);
        if (unlikely(error)) return error;
        space = (address_space_t *)data.object;
        if (space == current_thread->address_space) {
            obj_deref(&space->base);
            return EINVAL;
        }
    }

    address_space_t *orig_space = current_thread->address_space;
    unsigned char buffer[1024];

    do {
        size_t cur = sizeof(buffer);
        if (cur > size) cur = size;

        irq_state_t state = save_disable_irq();
        current_thread->address_space = space;
        pmap_switch(&space->pmap);
        restore_irq(state);

        error = memcpy_user(buffer, (const void *)src, cur);

        state = save_disable_irq();
        current_thread->address_space = orig_space;
        pmap_switch(orig_space ? &orig_space->pmap : NULL);
        restore_irq(state);

        if (unlikely(error)) break;

        error = memcpy_user(dest, buffer, cur);
        if (unlikely(error)) break;

        dest += cur;
        src += cur;
        size -= cur;
    } while (size > 0);

    obj_deref(&space->base);
    return error;
}
