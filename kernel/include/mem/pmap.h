#pragma once

#include "hydrogen/error.h"
#include <stddef.h>
#include <stdint.h>

#define PMAP_WRITE 1
#define PMAP_EXEC 2

typedef enum {
    CACHE_WRITEBACK,
    CACHE_WRITETHROUGH,
    CACHE_NONE_WEAK,
    CACHE_NONE,
    CACHE_WRITE_PROTECT,
    CACHE_WRITE_COMBINE,
} cache_mode_t;

extern uintptr_t min_kernel_address;

void init_pmap(void);
void pmap_init_switch(void);

hydrogen_error_t map_kernel_memory(uintptr_t virt, uint64_t phys, size_t size, int flags, cache_mode_t mode);

// you must reserve the memory first
hydrogen_error_t alloc_kernel_memory(uintptr_t virt, size_t size, int flags);

void remap_memory(uintptr_t virt, size_t size, int flags);

// any memory that was mapped with alloc_kernel_memory gets freed but not unreserved
void unmap_memory(uintptr_t virt, size_t size);
