#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// panics on failure
void kvmm_add_range(uintptr_t head, uintptr_t tail);

// returns 0 on failure
uintptr_t kvmm_alloc(size_t size);
bool kvmm_resize(uintptr_t address, size_t old_size, size_t new_size);
void kvmm_free(uintptr_t address, size_t size);
