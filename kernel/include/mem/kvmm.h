#pragma once

#include "hydrogen/error.h"
#include "mem/pmap.h"
#include <stddef.h>
#include <stdint.h>

// panics on failure
void kvmm_add_range(uintptr_t start, size_t size);

hydrogen_error_t kvmm_alloc(uintptr_t *out, size_t size);
void kvmm_free(uintptr_t start, size_t size);

hydrogen_error_t map_phys_mem(void **out, uint64_t addr, size_t size, int flags, cache_mode_t mode);
void unmap_phys_mem(const void *ptr, size_t size);
