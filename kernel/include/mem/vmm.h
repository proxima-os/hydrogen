#pragma once

#include "hydrogen/memory.h"
#include "hydrogen/types.h"
#include "mem/pmap.h"
#include "proc/mutex.h"
#include "util/list.h"
#include "util/object.h"
#include <stddef.h>
#include <stdint.h>

#define VMM_PERM_FLAGS (HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE | HYDROGEN_MEM_EXEC)
#define VMM_REGION_FLAGS (VMM_PERM_FLAGS | HYDROGEN_MEM_LAZY_RESERVE)
#define VMM_MAP_FLAGS (VMM_REGION_FLAGS | HYDROGEN_MEM_EXACT | HYDROGEN_MEM_OVERWRITE)

typedef struct mem_object mem_object_t;
typedef struct vmm_region vmm_region_t;
typedef struct vmm vmm_t;

typedef struct {
    object_ops_t base;
    void (*post_map)(mem_object_t *self, vmm_t *vmm, uintptr_t head, uintptr_t tail, unsigned flags, size_t offset);
    hydrogen_ret_t (*get_page)(mem_object_t *self, vmm_region_t *region, size_t offset);
} mem_object_ops_t;

struct mem_object {
    object_t base;
    list_t regions;
    mutex_t regions_lock;
};

struct vmm_region {
    vmm_t *vmm;
    vmm_region_t *parent;
    vmm_region_t *left;
    vmm_region_t *right;
    list_node_t node;
    uintptr_t head;
    uintptr_t tail;
    int balance;
    unsigned flags;
    mem_object_t *object;
    object_rights_t rights;
    size_t offset;
    list_node_t object_node;
};

struct vmm {
    object_t base;
    mutex_t lock;
    pmap_t pmap;
    vmm_region_t *regtree;
    list_t regions;
    size_t num_mapped;
    size_t num_reserved;
    size_t num_tables;
};

int vmm_create(vmm_t **out);
int vmm_clone(vmm_t **out, vmm_t *src);

hydrogen_ret_t vmm_map(
        vmm_t *vmm,
        uintptr_t hint,
        size_t size,
        unsigned flags,
        mem_object_t *object,
        object_rights_t rights,
        size_t offset
);
int vmm_remap(vmm_t *vmm, uintptr_t address, size_t size, unsigned flags);
hydrogen_ret_t vmm_move(
        vmm_t *vmm,
        uintptr_t addr,
        size_t size,
        vmm_t *dest_vmm,
        uintptr_t dest_addr,
        size_t dest_size
);
int vmm_unmap(vmm_t *vmm, uintptr_t address, size_t size);

// vmm must be locked!
vmm_region_t *vmm_get_region(vmm_t *vmm, uintptr_t address);
