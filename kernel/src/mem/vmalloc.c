#include "mem/vmalloc.h"
#include "hydrogen/error.h"
#include "hydrogen/memory.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/kmalloc.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "string.h"
#include <stddef.h>
#include <stdint.h>

#define ZERO_PTR ((void *)_Alignof(max_align_t))

void *vmalloc(size_t size) {
    if (unlikely(size == 0)) return ZERO_PTR;
    if (likely(size <= PAGE_SIZE)) return kmalloc(size);

    size = (size + PAGE_MASK) & ~PAGE_MASK;

    uintptr_t addr;
    hydrogen_error_t error = kvmm_alloc(&addr, size);
    if (unlikely(error)) return NULL;

    pmap_alloc(addr, size, HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE);
    return (void *)addr;
}

void vmfree(void *ptr, size_t size) {
    if (likely(size <= PAGE_SIZE)) return kfree(ptr, size);

    size = (size + PAGE_MASK) & ~PAGE_MASK;

    pmap_unmap(NULL, (uintptr_t)ptr, size);
    kvmm_free((uintptr_t)ptr, size);
}
