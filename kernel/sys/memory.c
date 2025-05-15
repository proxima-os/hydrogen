#include "hydrogen/memory.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "hydrogen/handle.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "kernel/return.h"
#include "mem/memmap.h"
#include "mem/object/anonymous.h"
#include "mem/pmap.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/mutex.h"
#include "proc/sched.h"
#include "string.h"
#include "sys/memory.h"
#include "sys/syscall.h"
#include "util/handle.h"
#include "util/hash.h"
#include "util/hlist.h"
#include "util/list.h"
#include "util/object.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VMM_RIGHTS THIS_VMM_RIGHTS

const size_t hydrogen_page_size = PAGE_SIZE;

hydrogen_ret_t hydrogen_vmm_create(uint32_t flags) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return ret_error(EINVAL);

    vmm_t *vmm;
    int error = vmm_create(&vmm);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = hnd_alloc(&vmm->base, VMM_RIGHTS, flags);
    obj_deref(&vmm->base);
    return ret;
}

hydrogen_ret_t hydrogen_vmm_clone(int vmm_hnd, uint32_t flags) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return ret_error(EINVAL);

    vmm_t *src;
    int error = vmm_or_this(&src, vmm_hnd, HYDROGEN_VMM_CLONE);
    if (unlikely(error)) return ret_error(error);

    vmm_t *vmm;
    error = vmm_clone(&vmm, src);
    if (unlikely(error)) goto err;

    hydrogen_ret_t ret = hnd_alloc(&vmm->base, VMM_RIGHTS, flags);
    obj_deref(&vmm->base);
    if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&src->base);
    return ret;
err:
    if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&src->base);
    return ret_error(error);
}

hydrogen_ret_t hydrogen_vmm_map(
        int vmm_hnd,
        uintptr_t hint,
        size_t size,
        uint32_t flags,
        int object_hnd,
        uint64_t offset
) {
    if (unlikely(((hint | size | offset) & PAGE_MASK) != 0)) return ret_error(EINVAL);
    if (unlikely((flags & ~VMM_MAP_FLAGS) != 0)) return ret_error(EINVAL);
    if (object_hnd < 0 && unlikely(object_hnd != HYDROGEN_INVALID_HANDLE)) return ret_error(EBADF);

    vmm_t *vmm;
    int error = vmm_or_this(&vmm, vmm_hnd, HYDROGEN_VMM_MAP);
    if (unlikely(error)) return ret_error(error);

    mem_object_t *object;
    object_rights_t rights;

    if (object_hnd != HYDROGEN_INVALID_HANDLE) {
        handle_data_t data;
        error = hnd_resolve(&data, object_hnd, OBJECT_MEMORY, 0);

        if (unlikely(error)) {
            if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&vmm->base);
            return ret_error(error);
        }

        object = (mem_object_t *)data.object;
        rights = data.rights;
    } else {
        object = NULL;
        rights = 0;
    }

    hydrogen_ret_t ret = vmm_map(vmm, hint, size, flags, object, rights, 0);
    if (object_hnd != HYDROGEN_INVALID_HANDLE) obj_deref(&object->base);
    if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&vmm->base);
    return ret;
}

int hydrogen_vmm_remap(int vmm_hnd, uintptr_t address, size_t size, uint32_t flags) {
    if (unlikely(((address | size) & PAGE_MASK) != 0)) return EINVAL;
    if (unlikely((flags & ~VMM_PERM_FLAGS) != 0)) return EINVAL;

    vmm_t *vmm;
    int error = vmm_or_this(&vmm, vmm_hnd, HYDROGEN_VMM_REMAP);
    if (unlikely(error)) return error;

    error = vmm_remap(vmm, address, size, flags);
    if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&vmm->base);
    return error;
}

hydrogen_ret_t hydrogen_vmm_move(
        int src_vmm_hnd,
        uintptr_t src_addr,
        size_t src_size,
        int dst_vmm_hnd,
        uintptr_t dst_addr,
        size_t dst_size
) {
    if (unlikely(((src_addr | src_size | dst_addr | dst_size) & PAGE_MASK) != 0)) return ret_error(EINVAL);
    if (unlikely(src_size > dst_size)) return ret_error(EINVAL);
    if (dst_vmm_hnd < 0 && unlikely(dst_vmm_hnd != HYDROGEN_THIS_VMM)) return ret_error(EBADF);

    vmm_t *src_vmm;
    int error = vmm_or_this(&src_vmm, src_vmm_hnd, HYDROGEN_VMM_UNMAP | HYDROGEN_VMM_READ);
    if (unlikely(error)) return ret_error(error);

    vmm_t *dst_vmm;
    error = vmm_or_this(&dst_vmm, dst_vmm_hnd, HYDROGEN_VMM_MAP);

    if (unlikely(error)) {
        if (src_vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&src_vmm->base);
        return ret_error(error);
    }

    hydrogen_ret_t ret = vmm_move(src_vmm, src_addr, src_size, dst_vmm, dst_addr, dst_size);
    if (dst_vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&dst_vmm->base);
    if (src_vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&src_vmm->base);
    return ret;
}

int hydrogen_vmm_unmap(int vmm_hnd, uintptr_t address, size_t size) {
    if (unlikely(((address | size) & PAGE_MASK) != 0)) return EINVAL;

    vmm_t *vmm;
    int error = vmm_or_this(&vmm, vmm_hnd, HYDROGEN_VMM_UNMAP);
    if (unlikely(error)) return error;

    error = vmm_unmap(vmm, address, size);
    if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&vmm->base);
    return error;
}

#define BUFFER_SIZE 1024

int hydrogen_vmm_read(int vmm_hnd, void *buffer, uintptr_t address, size_t size) {
    if (unlikely(size == 0)) return 0;

    int error = verify_user_buffer((uintptr_t)buffer, size);
    if (unlikely(error)) return error;

    error = verify_user_buffer(address, size);
    if (unlikely(error)) return error;

    if (vmm_hnd == HYDROGEN_THIS_VMM) {
        return user_memcpy(buffer, (const void *)address, size);
    }

    handle_data_t data;
    error = hnd_resolve(&data, vmm_hnd, OBJECT_VMM, HYDROGEN_VMM_READ);
    if (unlikely(error)) return error;
    vmm_t *vmm = (vmm_t *)data.object;

    unsigned char buf[BUFFER_SIZE];

    do {
        size_t cur = sizeof(buf);
        if (cur > size) cur = size;

        vmm_t *orig = vmm_switch(vmm);
        error = user_memcpy(buf, (const void *)address, cur);
        vmm_switch(orig);
        if (unlikely(error)) break;

        error = user_memcpy(buffer, buf, cur);
        if (unlikely(error)) break;
    } while (size > 0);

    obj_deref(&vmm->base);
    return error;
}

int hydrogen_vmm_write(int vmm_hnd, const void *buffer, uintptr_t address, size_t size) {
    if (unlikely(size == 0)) return 0;

    int error = verify_user_buffer((uintptr_t)buffer, size);
    if (unlikely(error)) return error;

    error = verify_user_buffer(address, size);
    if (unlikely(error)) return error;

    if (vmm_hnd == HYDROGEN_THIS_VMM) {
        return user_memcpy((void *)address, buffer, size);
    }

    handle_data_t data;
    error = hnd_resolve(&data, vmm_hnd, OBJECT_VMM, HYDROGEN_VMM_READ);
    if (unlikely(error)) return error;
    vmm_t *vmm = (vmm_t *)data.object;

    unsigned char buf[BUFFER_SIZE];

    do {
        size_t cur = sizeof(buf);
        if (cur > size) cur = size;

        error = user_memcpy(buf, buffer, cur);
        if (unlikely(error)) break;

        vmm_t *orig = vmm_switch(vmm);
        error = user_memcpy((void *)address, buf, cur);
        vmm_switch(orig);
        if (unlikely(error)) break;
    } while (size > 0);

    obj_deref(&vmm->base);
    return error;
}

typedef struct {
    uint64_t vmm_id;
    uint64_t obj_id;
    uint64_t offset;
} futex_address_t;

// on success, the current vmm is locked
static int get_futex_address(futex_address_t *out, uint32_t *location) {
    uintptr_t address = (uintptr_t)location;

    if (unlikely((address & 3) != 0)) return EINVAL;

    int error = verify_user_buffer(address, sizeof(*location));
    if (unlikely(error)) return error;

    vmm_t *vmm = current_thread->vmm;
    rmutex_acq(&vmm->lock, 0, false);

    vmm_region_t *region = vmm_get_region(vmm, address);

    if (unlikely(!region)) {
        rmutex_rel(&vmm->lock);
        return EFAULT;
    }

    if (unlikely((region->flags & HYDROGEN_MEM_READ) == 0)) {
        rmutex_rel(&vmm->lock);
        return EFAULT;
    }

    if (region->object != NULL) {
        out->vmm_id = (region->flags & HYDROGEN_MEM_SHARED) == 0 ? vmm->id : SHARED_VM_ID;
        out->obj_id = region->object->id;
        out->offset = region->offset + (address - region->head);
        return 0;
    }

    // this ensures the page is faulted in
    uint32_t value;
    error = user_memcpy(&value, location, sizeof(value));
    if (unlikely(error)) {
        rmutex_rel(&vmm->lock);
        return error;
    }

    page_t *page = pmap_get_mapping(vmm, address);
    ASSERT(page != NULL);

    out->vmm_id = vmm->id;
    out->obj_id = ANON_OBJ_ID;
    out->offset = (page->anon.id << PAGE_SHIFT) | (address & PAGE_MASK);

    return 0;
}

typedef struct {
    hlist_node_t node;
    futex_address_t address;
    uint64_t hash;
    mutex_t lock;
    list_t waiters;
} futex_location_t;

static hlist_t *futex_table;
static size_t futex_table_cap;
static size_t futex_table_cnt;
static mutex_t futex_table_lock;

static bool maybe_expand(void) {
    if (futex_table_cnt < futex_table_cap - (futex_table_cap / 4)) return true;

    size_t new_cap = futex_table_cap ? futex_table_cap * 2 : 8;
    size_t new_siz = new_cap * sizeof(*futex_table);
    hlist_t *new_table = vmalloc(new_siz);
    if (unlikely(!new_table)) return false;
    memset(new_table, 0, new_siz);

    for (size_t i = 0; i < futex_table_cap; i++) {
        for (;;) {
            futex_location_t *location = HLIST_REMOVE_HEAD(futex_table[i], futex_location_t, node);
            if (!location) break;
            hlist_insert_head(&new_table[location->hash & (new_cap - 1)], &location->node);
        }
    }

    vfree(futex_table, futex_table_cap * sizeof(*futex_table));
    futex_table = new_table;
    futex_table_cap = new_cap;
    return true;
}

static futex_location_t *get_futex_location(futex_address_t *address, bool create) {
    uint64_t hash = make_hash_blob(address, sizeof(*address));
    futex_location_t *current;

    if (futex_table_cap != 0) {
        current = HLIST_HEAD(futex_table[hash & (futex_table_cap - 1)], futex_location_t, node);

        while (current != NULL && (current->hash != hash && memcmp(&current->address, address, sizeof(*address)))) {
            current = HLIST_NEXT(*current, futex_location_t, node);
        }
    } else {
        current = NULL;
    }

    if (create && current == NULL) {
        current = vmalloc(sizeof(*current));
        if (unlikely(!current)) return current;

        if (unlikely(!maybe_expand())) {
            vfree(current, sizeof(*current));
            return NULL;
        }

        memset(current, 0, sizeof(*current));
        current->address = *address;
        current->hash = hash;

        hlist_insert_head(&futex_table[hash & (futex_table_cap - 1)], &current->node);
    }

    return current;
}

static void free_location_or_unlock(futex_location_t *location) {
    if (list_empty(&location->waiters)) {
        size_t bucket = location->hash & (futex_table_cap - 1);
        hlist_remove(&futex_table[bucket], &location->node);
        futex_table_cnt -= 1;
        vfree(location, sizeof(*location));
    } else {
        mutex_rel(&location->lock);
    }
}

int hydrogen_memory_wait(uint32_t *location, uint32_t expected, uint64_t deadline) {
    futex_address_t addr;
    int error = get_futex_address(&addr, location);
    if (unlikely(error)) return error;

    vmm_t *vmm = current_thread->vmm;
    mutex_acq(&futex_table_lock, 0, false);

    futex_location_t *loc = get_futex_location(&addr, true);

    if (unlikely(!loc)) {
        mutex_rel(&futex_table_lock);
        rmutex_rel(&vmm->lock);
        return ENOMEM;
    }

    mutex_acq(&loc->lock, 0, false);

    uint32_t value;
    error = user_memcpy(&value, location, sizeof(value));
    if (unlikely(error)) {
        free_location_or_unlock(loc);
        mutex_rel(&futex_table_lock);
        rmutex_rel(&vmm->lock);
        return error;
    }

    if (unlikely(value != expected)) {
        free_location_or_unlock(loc);
        mutex_rel(&futex_table_lock);
        rmutex_rel(&vmm->lock);
        return EAGAIN;
    }

    list_insert_tail(&loc->waiters, &current_thread->wait_node);
    sched_prepare_wait(true);
    mutex_rel(&loc->lock);
    mutex_rel(&futex_table_lock);
    rmutex_rel(&vmm->lock);

    error = sched_perform_wait(deadline);

    // note: while it may seem like these locks can be avoided on success by making hydrogen_memory_wake
    // remove the node, that's not the case; doing so would result in a race condition where this thread
    // uses wait_node for something else before hydrogen_memory_wake has removed the node from the wait list
    mutex_acq(&futex_table_lock, 0, false);
    mutex_acq(&loc->lock, 0, false);
    list_remove(&loc->waiters, &current_thread->wait_node);
    free_location_or_unlock(loc);
    mutex_rel(&futex_table_lock);

    return error;
}

hydrogen_ret_t hydrogen_memory_wake(uint32_t *location, size_t count) {
    futex_address_t addr;
    int error = get_futex_address(&addr, location);
    if (unlikely(error)) return ret_error(error);

    vmm_t *vmm = current_thread->vmm;
    mutex_acq(&futex_table_lock, 0, false);

    futex_location_t *loc = get_futex_location(&addr, false);

    if (unlikely(!loc)) {
        mutex_rel(&futex_table_lock);
        rmutex_rel(&vmm->lock);
        return ret_integer(0);
    }

    mutex_acq(&loc->lock, 0, false);

    size_t awoken = 0;
    thread_t *waiter = LIST_HEAD(loc->waiters, thread_t, wait_node);

    while ((count == 0 || awoken < count) && waiter != NULL) {
        if (sched_wake(waiter)) awoken += 1;
        waiter = LIST_NEXT(*waiter, thread_t, wait_node);
    }

    mutex_rel(&loc->lock);
    mutex_rel(&futex_table_lock);
    rmutex_rel(&vmm->lock);
    return ret_integer(awoken);
}

#define MEM_OBJECT_RIGHTS (HYDROGEN_MEM_OBJECT_READ | HYDROGEN_MEM_OBJECT_WRITE | HYDROGEN_MEM_OBJECT_EXEC)

hydrogen_ret_t hydrogen_mem_object_create(size_t size, uint32_t flags) {
    if (unlikely((size & PAGE_MASK) != 0)) return ret_error(EINVAL);
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return ret_error(EINVAL);

    mem_object_t *object;
    int error = anon_mem_object_create(&object, size >> PAGE_SHIFT);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = hnd_alloc(&object->base, MEM_OBJECT_RIGHTS, flags);
    obj_deref(&object->base);
    return ret;
}

int hydrogen_mem_object_resize(int object, size_t size) {
    if (unlikely((size & PAGE_MASK) != 0)) return EINVAL;

    handle_data_t data;
    int error = hnd_resolve(&data, object, OBJECT_MEMORY, HYDROGEN_MEM_OBJECT_WRITE);
    if (unlikely(error)) return error;

    error = anon_mem_object_resize((mem_object_t *)data.object, size >> PAGE_SHIFT);
    obj_deref(data.object);
    return error;
}

int hydrogen_mem_object_read(int object_hnd, void *buffer, size_t count, uint64_t position) {
    if (unlikely(count == 0)) return 0;

    int error = verify_user_buffer((uintptr_t)buffer, count);
    if (unlikely(error)) return error;

    handle_data_t data;
    error = hnd_resolve(&data, object_hnd, OBJECT_MEMORY, HYDROGEN_MEM_OBJECT_READ);
    if (unlikely(error)) return error;

    error = mem_object_read((mem_object_t *)data.object, buffer, count, position);

    obj_deref(data.object);
    return error;
}

int hydrogen_mem_object_write(int object_hnd, const void *buffer, size_t count, uint64_t position) {
    if (unlikely(count == 0)) return 0;

    int error = verify_user_buffer((uintptr_t)buffer, count);
    if (unlikely(error)) return error;

    handle_data_t data;
    error = hnd_resolve(&data, object_hnd, OBJECT_MEMORY, HYDROGEN_MEM_OBJECT_WRITE);
    if (unlikely(error)) return error;

    error = mem_object_write((mem_object_t *)data.object, buffer, count, position);

    obj_deref(data.object);
    return error;
}
