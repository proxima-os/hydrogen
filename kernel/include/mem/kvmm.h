#pragma once

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
