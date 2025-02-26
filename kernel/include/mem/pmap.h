#pragma once

#include "hydrogen/error.h"
#include "hydrogen/memory.h"
#include "util/spinlock.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t *root;
    struct cpu *cpus;
    size_t ncpus;
    spinlock_t cpus_lock;
} pmap_t;

extern uintptr_t max_user_address;
extern uintptr_t min_kernel_address;

void init_pmap(void);
void pmap_init_switch(void);

hydrogen_error_t pmap_create(pmap_t *out);
void pmap_destroy(pmap_t *pmap);

// Must be called with IRQs disabled
void pmap_switch(pmap_t *target);

// if pmap != NULL, these functions don't do any locking themselves
hydrogen_error_t pmap_prepare(pmap_t *pmap, uintptr_t addr, size_t size);
void pmap_map(pmap_t *pmap, uintptr_t addr, size_t size, uint64_t phys, hydrogen_mem_flags_t flags);
void pmap_alloc(uintptr_t addr, size_t size, hydrogen_mem_flags_t flags);
void pmap_clone(pmap_t *pmap, pmap_t *src, uintptr_t addr, size_t size, bool cow); // anon pages must be rereserved
void pmap_remap(pmap_t *pmap, uintptr_t addr, size_t size, hydrogen_mem_flags_t flags);
void pmap_unmap(pmap_t *pmap, uintptr_t addr, size_t size);

// panic on failure
void pmap_init_map(uintptr_t addr, size_t size, uint64_t phys, hydrogen_mem_flags_t flags);
