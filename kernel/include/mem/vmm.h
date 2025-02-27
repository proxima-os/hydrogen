#pragma once

#include "hydrogen/error.h"
#include "hydrogen/memory.h"
#include "mem/pmap.h"
#include "thread/mutex.h"
#include "util/handle.h"
#include "util/object.h"
#include <stdint.h>

#define VM_PERM_MASK (HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE | HYDROGEN_MEM_EXEC)
#define VM_CACHE_MODE_MASK (HYDROGEN_MEM_WRITE_COMBINE | HYDROGEN_MEM_WRITE_THROUGH | HYDROGEN_MEM_NO_CACHE)
#define VM_REGION_FLAG_MASK (VM_PERM_MASK | HYDROGEN_MEM_SHARED | VM_CACHE_MODE_MASK)
#define VM_MAP_FLAG_MASK (HYDROGEN_MEM_EXACT | HYDROGEN_MEM_OVERWRITE)

typedef struct vm_object vm_object_t;
typedef struct vm_region vm_region_t;
typedef struct address_space address_space_t;

typedef struct {
    object_ops_t base;
    // WARNING: Do not rely on `region` staying valid after this call returns!
    hydrogen_error_t (*on_map)(vm_object_t *self, vm_region_t *region);
    hydrogen_error_t (*get_phys)(vm_object_t *self, uint64_t *out, vm_region_t *region, size_t offset);
} vm_object_ops_t;

struct vm_object {
    object_t base;
};

struct vm_region {
    vm_region_t *parent;
    vm_region_t *left;
    vm_region_t *right;
    vm_region_t *prev;
    vm_region_t *next;
    uintptr_t head;
    uintptr_t tail;
    int balance;
    hydrogen_mem_flags_t flags;
    handle_data_t object;
    size_t offset; // For object mappings
};

struct address_space {
    object_t base;
    mutex_t lock;
    pmap_t pmap;
    vm_region_t *regtree;
    vm_region_t *regions;
    size_t num_mapped;   // the number of pages that are mapped in this address space
    size_t num_reserved; // the number of pages that are reserved for this address space
};

void vm_switch(address_space_t *space);

hydrogen_error_t vm_unmap(address_space_t *space, uintptr_t addr, size_t size);

void vm_obj_init(vm_object_t *obj, const vm_object_ops_t *ops);

// `space` must be locked
vm_region_t *vm_get_region(address_space_t *space, uintptr_t address);
