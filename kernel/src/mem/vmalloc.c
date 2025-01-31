#include "mem/vmalloc.h"
#include "hydrogen/error.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/kmalloc.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "mem/pmm.h"
#include "string.h"
#include <stddef.h>
#include <stdint.h>

#define ZERO_PTR ((void *)_Alignof(max_align_t))

void *vmalloc(size_t size) {
    if (unlikely(size == 0)) return ZERO_PTR;
    if (likely(size <= PAGE_SIZE)) return kmalloc(size);

    size = (size + PAGE_MASK) & ~PAGE_MASK;
    size_t pages = size >> PAGE_SHIFT;

    if (!pmm_reserve(pages)) return NULL;

    uintptr_t addr;
    hydrogen_error_t error = kvmm_alloc(&addr, size);
    if (unlikely(error)) {
        pmm_unreserve(pages);
        return NULL;
    }

    error = alloc_kernel_memory(addr, size, PMAP_WRITE);
    if (unlikely(error)) {
        kvmm_free(addr, size);
        pmm_unreserve(pages);
        return NULL;
    }

    return (void *)addr;
}

void vmfree(void *ptr, size_t size) {
    if (likely(size <= PAGE_SIZE)) return kfree(ptr, size);

    size = (size + PAGE_MASK) & ~PAGE_MASK;
    size_t pages = size >> PAGE_SHIFT;

    unmap_memory((uintptr_t)ptr, size);
    kvmm_free((uintptr_t)ptr, size);
    pmm_unreserve(pages);
}
