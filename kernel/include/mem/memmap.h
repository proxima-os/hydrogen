#pragma once

#include <stddef.h>
#include <stdint.h>

extern uintptr_t hhdm_base;

void memmap_init(void);
void *early_alloc_page(void);

static inline void *phys_to_virt(uint64_t phys) {
    return (void *)(hhdm_base + phys);
}

static inline uint64_t virt_to_phys(void *virt) {
    return (uintptr_t)virt - hhdm_base;
}

