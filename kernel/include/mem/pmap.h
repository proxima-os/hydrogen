#pragma once

#include "arch/memmap.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void pmap_init(void);
void pmap_init_switch(void);

void pmap_early_map(uintptr_t virt, uint64_t phys, size_t size, int flags);
void pmap_early_alloc(uintptr_t virt, size_t size, int flags);

static inline bool is_kernel_address(uintptr_t virt) {
    return virt & (1ul << (cpu_vaddr_bits() - 1));
}
