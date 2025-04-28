#include "hydrogen/memory.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "kernel/syscall.h"
#include "syscall.h"
#include "vdso.h"
#include <stddef.h>
#include <stdint.h>

EXPORT const size_t hydrogen_page_size = PAGE_SIZE;

EXPORT hydrogen_ret_t hydrogen_vm_create(void) {
    hydrogen_handle_t ret;
    int error;
    SYSCALL0(SYSCALL_VM_CREATE);
    return (hydrogen_ret_t){.error = error, .handle = ret};
}

EXPORT hydrogen_ret_t hydrogen_vm_clone(hydrogen_handle_t src) {
    hydrogen_handle_t ret;
    int error;
    SYSCALL1(SYSCALL_VM_CLONE, src);
    return (hydrogen_ret_t){.error = error, .handle = ret};
}

EXPORT hydrogen_ret_t hydrogen_vm_map(
        hydrogen_handle_t vm,
        uintptr_t addr,
        size_t size,
        unsigned flags,
        hydrogen_handle_t object,
        size_t offset
) {
    void *ret;
    size_t error;
    SYSCALL6(SYSCALL_VM_MAP, vm, addr, size, flags, object, offset);
    return (hydrogen_ret_t){.error = error, .handle = ret};
}

EXPORT hydrogen_ret_t hydrogen_vm_map_vdso(hydrogen_handle_t vm) {
    void *ret;
    int error;
    SYSCALL1(SYSCALL_VM_MAP_VDSO, vm);
    return (hydrogen_ret_t){.error = error, .handle = ret};
}

EXPORT hydrogen_ret_t hydrogen_vm_move(
        hydrogen_handle_t vm,
        uintptr_t addr,
        size_t size,
        hydrogen_handle_t dest_vm,
        uintptr_t dest_addr,
        size_t dest_size
) {
    void *ret;
    int error;
    SYSCALL6(SYSCALL_VM_MOVE, vm, addr, size, dest_vm, dest_addr, dest_size);
    return (hydrogen_ret_t){.error = error, .pointer = ret};
}

EXPORT int hydrogen_vm_remap(hydrogen_handle_t vm, uintptr_t addr, size_t size, unsigned flags) {
    UNUSED int ret;
    int error;
    SYSCALL4(SYSCALL_VM_REMAP, vm, addr, size, flags);
    return error;
}

EXPORT int hydrogen_vm_unmap(hydrogen_handle_t vm, uintptr_t addr, size_t size) {
    UNUSED int ret;
    int error;
    SYSCALL3(SYSCALL_VM_UNMAP, vm, addr, size);
    return error;
}

EXPORT int hydrogen_vm_write(hydrogen_handle_t vm, uintptr_t dest, const void *src, size_t size) {
    UNUSED int ret;
    int error;
    SYSCALL4(SYSCALL_VM_WRITE, vm, dest, src, size);
    return error;
}

EXPORT int hydrogen_vm_fill(hydrogen_handle_t vm, uintptr_t dest, uint8_t value, size_t size) {
    UNUSED int ret;
    int error;
    SYSCALL4(SYSCALL_VM_FILL, vm, dest, value, size);
    return error;
}

EXPORT int hydrogen_vm_read(hydrogen_handle_t vm, void *dest, uintptr_t src, size_t size) {
    UNUSED int ret;
    int error;
    SYSCALL4(SYSCALL_VM_READ, vm, dest, src, size);
    return error;
}
