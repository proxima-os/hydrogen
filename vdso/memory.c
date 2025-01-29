#include "hydrogen/memory.h"
#include "compiler.h"
#include "sys/sysvecs.h"
#include "syscall.h"

intptr_t hydrogen_map_memory(uintptr_t preferred, size_t size, int flags, int fd, uint64_t offset) {
    syscall_result_t result = syscall5(SYS_MMAP, preferred, size, flags, fd, offset);
    return unlikely(result.error) ? -result.error : (intptr_t)result.value.num;
}

int hydrogen_set_memory_protection(uintptr_t start, size_t size, int flags) {
    return syscall3(SYS_MPROTECT, start, size, flags).error;
}

int hydrogen_unmap_memory(uintptr_t start, size_t size) {
    return syscall2(SYS_MUNMAP, start, size).error;
}
