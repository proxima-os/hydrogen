#include "mem/vmalloc.h"
#include "arch/pmap.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/kmalloc.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "string.h"
#include <stdbool.h>
#include <stdint.h>

void *vmalloc(size_t size) {
    if (likely(size <= PAGE_SIZE)) return kmalloc(size);

    size = (size + PAGE_MASK) & ~PAGE_MASK;
    size_t pages = size >> PAGE_SHIFT;

    if (unlikely(!pmem_reserve(pages))) return NULL;

    uintptr_t vaddr = kvmm_alloc(size);
    if (unlikely(!vaddr)) goto err;
    if (unlikely(!pmap_prepare(NULL, vaddr, size))) goto err2;

    pmap_alloc(NULL, vaddr, size, PMAP_READABLE | PMAP_WRITABLE);
    return (void *)vaddr;
err2:
    kvmm_free(vaddr, size);
err:
    pmem_unreserve(pages);
    return NULL;
}

void *vrealloc(void *ptr, size_t old_size, size_t new_size) {
    bool old_kmalloc = old_size <= PAGE_SIZE;
    bool new_kmalloc = new_size <= PAGE_SIZE;

    if (likely(old_kmalloc == new_kmalloc)) {
        if (likely(old_kmalloc)) return krealloc(ptr, old_size, new_size);

        old_size = (old_size + PAGE_MASK) & ~PAGE_MASK;
        new_size = (new_size + PAGE_MASK) & ~PAGE_MASK;
        if (old_size == new_size) return ptr;

        size_t delta;

        if (old_size < new_size) {
            delta = (new_size - old_size);
            if (unlikely(!pmem_reserve(delta >> PAGE_SHIFT))) return NULL;
        } else {
            delta = old_size - new_size;
        }

        if (unlikely(!kvmm_resize((uintptr_t)ptr, old_size, new_size, true))) {
            uintptr_t new_addr = kvmm_alloc(new_size);
            if (unlikely(new_addr == 0)) {
                if (old_size < new_size) pmem_unreserve(delta >> PAGE_SHIFT);
                return NULL;
            }

            if (unlikely(!pmap_prepare(NULL, new_addr, new_size))) {
                kvmm_free(new_addr, new_size);
                if (old_size < new_size) pmem_unreserve(delta >> PAGE_SHIFT);
                return NULL;
            }

            pmap_move(NULL, (uintptr_t)ptr, NULL, new_addr, old_size < new_size ? old_size : new_size);
            kvmm_free((uintptr_t)ptr, old_size);
            ptr = (void *)new_addr;
        }

        if (old_size < new_size) {
            pmap_alloc(NULL, (uintptr_t)ptr + old_size, delta, PMAP_READABLE | PMAP_WRITABLE);
        } else {
            pmem_unreserve(delta >> PAGE_SHIFT);
        }

        return ptr;
    }

    // Transitioning between allocators, no option but to copy
    void *ptr2 = vmalloc(new_size);
    if (unlikely(!ptr2)) return NULL;
    memcpy(ptr2, ptr, old_size < new_size ? old_size : new_size);
    vfree(ptr, old_size);
    return ptr2;
}

void vfree(void *ptr, size_t size) {
    if (likely(size <= PAGE_SIZE)) return kfree(ptr, size);

    size = (size + PAGE_MASK) & ~PAGE_MASK;
    pmap_unmap(NULL, (uintptr_t)ptr, size);
    kvmm_free((uintptr_t)ptr, size);
    pmem_unreserve(size >> PAGE_SHIFT);
}
