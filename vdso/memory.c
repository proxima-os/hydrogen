#include "hydrogen/memory.h"
#include "hydrogen/error.h"
#include "hydrogen/handle.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "kernel/syscall.h"
#include "syscall.h"
#include <stddef.h>
#include <stdint.h>

const size_t hydrogen_page_size = PAGE_SIZE;

hydrogen_error_t hydrogen_vm_create(hydrogen_handle_t *vm) {
    hydrogen_handle_t ret;
    hydrogen_error_t error;
    SYSCALL0(SYSCALL_VM_CREATE);
    if (likely(!error)) *vm = ret;
    return error;
}

hydrogen_error_t hydrogen_vm_clone(hydrogen_handle_t *vm, hydrogen_handle_t src) {
    hydrogen_handle_t ret;
    hydrogen_error_t error;
    SYSCALL1(SYSCALL_VM_CLONE, src);
    if (likely(!error)) *vm = ret;
    return error;
}

hydrogen_error_t hydrogen_vm_map(
    hydrogen_handle_t vm,
    uintptr_t *addr,
    size_t size,
    hydrogen_mem_flags_t flags,
    hydrogen_handle_t object,
    size_t offset
) {
    uintptr_t ret;
    hydrogen_error_t error;
    SYSCALL6(SYSCALL_VM_MAP, vm, *addr, size, flags, object, offset);
    if (likely(!error)) *addr = ret;
    return error;
}

hydrogen_error_t hydrogen_vm_map_vdso(hydrogen_handle_t vm, uintptr_t *addr) {
    uintptr_t ret;
    hydrogen_error_t error;
    SYSCALL1(SYSCALL_VM_MAP_VDSO, vm);
    if (likely(!error)) *addr = ret;
    return error;
}

hydrogen_error_t hydrogen_vm_remap(hydrogen_handle_t vm, uintptr_t addr, size_t size, hydrogen_mem_flags_t flags) {
    UNUSED int ret;
    hydrogen_error_t error;
    SYSCALL4(SYSCALL_VM_REMAP, vm, addr, size, flags);
    return error;
}

hydrogen_error_t hydrogen_vm_unmap(hydrogen_handle_t vm, uintptr_t addr, size_t size) {
    UNUSED int ret;
    hydrogen_error_t error;
    SYSCALL3(SYSCALL_VM_UNMAP, vm, addr, size);
    return error;
}
