#include "hydrogen/memory.h"
#include "cpu/cpudata.h"
#include "hydrogen/handle.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "kernel/return.h"
#include "mem/usercopy.h"
#include "mem/vmm.h"
#include "sys/syscall.h"
#include "util/handle.h"
#include "util/object.h"
#include <stddef.h>
#include <stdint.h>

#define VMM_RIGHTS                                                                                         \
    (HYDROGEN_VMM_CLONE | HYDROGEN_VMM_MAP | HYDROGEN_VMM_REMAP | HYDROGEN_VMM_UNMAP | HYDROGEN_VMM_READ | \
     HYDROGEN_VMM_WRITE)

const size_t hydrogen_page_size = PAGE_SIZE;

int hydrogen_vmm_create(uint32_t flags) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return -EINVAL;

    vmm_t *vmm;
    int ret = -vmm_create(&vmm);
    if (unlikely(ret)) return ret;

    ret = hnd_alloc(&vmm->base, VMM_RIGHTS, flags);
    obj_deref(&vmm->base);
    return ret;
}

static int resolve_or_this(vmm_t **out, int handle, object_rights_t rights) {
    if (handle == HYDROGEN_THIS_VMM) {
        *out = current_thread->vmm;
        return 0;
    } else {
        handle_data_t data;
        int error = hnd_resolve(&data, handle, OBJECT_VMM, rights);
        if (unlikely(error)) return error;
        *out = (vmm_t *)data.object;
        return 0;
    }
}

int hydrogen_vmm_clone(int vmm_hnd, uint32_t flags) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return -EINVAL;

    vmm_t *src;
    int ret = -resolve_or_this(&src, vmm_hnd, HYDROGEN_VMM_CLONE);
    if (unlikely(ret)) return ret;

    vmm_t *vmm;
    ret = -vmm_clone(&vmm, src);
    if (unlikely(ret)) goto ret;

    ret = hnd_alloc(&vmm->base, VMM_RIGHTS, flags);
    obj_deref(&vmm->base);
ret:
    if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&src->base);
    return ret;
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
    int error = resolve_or_this(&vmm, vmm_hnd, HYDROGEN_VMM_MAP);
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
    int error = resolve_or_this(&vmm, vmm_hnd, HYDROGEN_VMM_REMAP);
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
    int error = resolve_or_this(&src_vmm, src_vmm_hnd, HYDROGEN_VMM_UNMAP | HYDROGEN_VMM_READ);
    if (unlikely(error)) return ret_error(error);

    vmm_t *dst_vmm;
    error = resolve_or_this(&dst_vmm, dst_vmm_hnd, HYDROGEN_VMM_MAP);

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
    int error = resolve_or_this(&vmm, vmm_hnd, HYDROGEN_VMM_UNMAP);
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
