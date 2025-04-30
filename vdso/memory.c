#include "hydrogen/memory.h"
#include "hydrogen/types.h"
#include "kernel/pgsize.h"
#include "kernel/syscall.h"
#include "syscall.h"
#include "vdso.h"
#include <stddef.h>
#include <stdint.h>

EXPORT const size_t hydrogen_page_size = PAGE_SIZE;

EXPORT hydrogen_ret_t hydrogen_vm_create(void) {
    return SYSCALL0(SYSCALL_VM_CREATE);
}

EXPORT hydrogen_ret_t hydrogen_vm_clone(hydrogen_handle_t src) {
    return SYSCALL1(SYSCALL_VM_CLONE, src);
}

EXPORT hydrogen_ret_t hydrogen_vm_map(
        hydrogen_handle_t vm,
        uintptr_t addr,
        size_t size,
        unsigned flags,
        hydrogen_handle_t object,
        size_t offset
) {
    return SYSCALL6(SYSCALL_VM_MAP, vm, addr, size, flags, object, offset);
}

EXPORT hydrogen_ret_t hydrogen_vm_map_vdso(hydrogen_handle_t vm) {
    return SYSCALL1(SYSCALL_VM_MAP_VDSO, vm);
}

EXPORT hydrogen_ret_t hydrogen_vm_move(
        hydrogen_handle_t vm,
        uintptr_t addr,
        size_t size,
        hydrogen_handle_t dest_vm,
        uintptr_t dest_addr,
        size_t dest_size
) {
    return SYSCALL6(SYSCALL_VM_MOVE, vm, addr, size, dest_vm, dest_addr, dest_size);
}

EXPORT int hydrogen_vm_remap(hydrogen_handle_t vm, uintptr_t addr, size_t size, unsigned flags) {
    return SYSCALL4(SYSCALL_VM_REMAP, vm, addr, size, flags).error;
}

EXPORT int hydrogen_vm_unmap(hydrogen_handle_t vm, uintptr_t addr, size_t size) {
    return SYSCALL3(SYSCALL_VM_UNMAP, vm, addr, size).error;
}

EXPORT int hydrogen_vm_write(hydrogen_handle_t vm, uintptr_t dest, const void *src, size_t size) {
    return SYSCALL4(SYSCALL_VM_WRITE, vm, dest, src, size).error;
}

EXPORT int hydrogen_vm_fill(hydrogen_handle_t vm, uintptr_t dest, uint8_t value, size_t size) {
    return SYSCALL4(SYSCALL_VM_FILL, vm, dest, value, size).error;
}

EXPORT int hydrogen_vm_read(hydrogen_handle_t vm, void *dest, uintptr_t src, size_t size) {
    return SYSCALL4(SYSCALL_VM_READ, vm, dest, src, size).error;
}
