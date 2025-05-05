#pragma once

#include "arch/memmap.h"
#include "errno.h"
#include "kernel/pgsize.h"
#include "mem/pmap.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// panics on failure
void kvmm_add_range(uintptr_t head, uintptr_t tail);

// returns 0 on failure
uintptr_t kvmm_alloc(size_t size);

// if `resize_mapping` is true:
//  when shrinking:
//   the area that has been removed will be unmapped with pmap_unmap
//  when growing:
//   the area that has been added will be prepared with pmap_prepare
// it's impossible for the caller to do this due to race conditions
bool kvmm_resize(uintptr_t address, size_t old_size, size_t new_size, bool resize_mapping);

void kvmm_free(uintptr_t address, size_t size);

static inline int map_mmio(uintptr_t *out, uint64_t phys, size_t size, int flags) {
    if (size == 0) return EINVAL;

    uint64_t tail = phys + (size - 1);
    if (tail < phys) return EINVAL;

    size_t offset = phys & PAGE_MASK;
    phys -= offset;
    tail |= PAGE_MASK;

    if (tail > cpu_max_phys_addr()) return EINVAL;

    size_t mapsiz = tail - phys + 1;
    uintptr_t addr = kvmm_alloc(mapsiz);
    if (addr == 0) return ENOMEM;

    if (!pmap_prepare(NULL, addr, mapsiz)) {
        kvmm_free(addr, mapsiz);
        return ENOMEM;
    }

    pmap_map(NULL, addr, phys, mapsiz, flags);
    *out = addr + offset;
    return 0;
}

static inline void unmap_mmio(uintptr_t addr, size_t size) {
    size_t offset = addr & PAGE_MASK;
    addr -= offset;
    size = (size + offset + PAGE_MASK) & ~PAGE_MASK;

    pmap_unmap(NULL, addr, size);
    kvmm_free(addr, size);
}
