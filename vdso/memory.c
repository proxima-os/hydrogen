#include "arch/syscall.h"
#include "kernel/pgsize.h"
#include "kernel/syscall.h"
#include "vdso.h"
#include <hydrogen/memory.h>
#include <hydrogen/types.h>
#include <stddef.h>

EXPORT const size_t hydrogen_page_size = PAGE_SIZE;

EXPORT hydrogen_ret_t hydrogen_vmm_create(uint32_t flags) {
    return SYSCALL1(SYSCALL_VMM_CREATE, flags);
}

EXPORT hydrogen_ret_t hydrogen_vmm_clone(int vmm, uint32_t flags) {
    return SYSCALL2(SYSCALL_VMM_CLONE, vmm, flags);
}

EXPORT hydrogen_ret_t
hydrogen_vmm_map(int vmm, uintptr_t hint, size_t size, uint32_t flags, int object, uint64_t offset) {
    return SYSCALL6(SYSCALL_VMM_MAP, vmm, hint, size, flags, object, offset);
}

EXPORT int hydrogen_vmm_remap(int vmm, uintptr_t address, size_t size, uint32_t flags) {
    return SYSCALL4(SYSCALL_VMM_REMAP, vmm, address, size, flags).error;
}

EXPORT hydrogen_ret_t
hydrogen_vmm_move(int src_vmm, uintptr_t src_addr, size_t src_size, int dst_vmm, uintptr_t dst_addr, size_t dst_size) {
    return SYSCALL6(SYSCALL_VMM_MOVE, src_vmm, src_addr, src_size, dst_vmm, dst_addr, dst_size);
}

EXPORT int hydrogen_vmm_unmap(int vmm, uintptr_t address, size_t size) {
    return SYSCALL3(SYSCALL_VMM_UNMAP, vmm, address, size).error;
}

EXPORT int hydrogen_vmm_read(int vmm, void *buffer, uintptr_t address, size_t size) {
    return SYSCALL4(SYSCALL_VMM_READ, vmm, buffer, address, size).error;
}

EXPORT int hydrogen_vmm_write(int vmm, const void *buffer, uintptr_t address, size_t size) {
    return SYSCALL4(SYSCALL_VMM_WRITE, vmm, buffer, address, size).error;
}

EXPORT int hydrogen_memory_wait(uint32_t *location, uint32_t expected, uint64_t deadline) {
    return SYSCALL3(SYSCALL_MEMORY_WAIT, location, expected, deadline).error;
}

EXPORT hydrogen_ret_t hydrogen_memory_wake(uint32_t *location, size_t count) {
    return SYSCALL2(SYSCALL_MEMORY_WAKE, location, count);
}

EXPORT hydrogen_ret_t hydrogen_mem_object_create(size_t size, uint32_t flags) {
    return SYSCALL2(SYSCALL_MEM_OBJECT_CREATE, size, flags);
}

EXPORT int hydrogen_mem_object_resize(int object, size_t size) {
    return SYSCALL2(SYSCALL_MEM_OBJECT_RESIZE, object, size).error;
}

EXPORT int hydrogen_mem_object_read(int object, void *buffer, size_t count, uint64_t position) {
    return SYSCALL4(SYSCALL_MEM_OBJECT_READ, object, buffer, count, position).error;
}

EXPORT int hydrogen_mem_object_write(int object, const void *buffer, size_t count, uint64_t position) {
    return SYSCALL4(SYSCALL_MEM_OBJECT_WRITE, object, buffer, count, position).error;
}
