#pragma once

#include "hydrogen/memory.h"
#include "mem/pmap.h"
#include "proc/mutex.h"
#include "util/list.h"
#include <stddef.h>
#include <stdint.h>

#define VMM_PERM_FLAGS (HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE | HYDROGEN_MEM_EXEC)
#define VMM_REGION_FLAGS (VMM_PERM_FLAGS | HYDROGEN_MEM_LAZY_RESERVE)
#define VMM_MAP_FLAGS (VMM_REGION_FLAGS | HYDROGEN_MEM_EXACT | HYDROGEN_MEM_OVERWRITE)

typedef struct vmm_region vmm_region_t;
typedef struct vmm vmm_t;

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
};

struct vmm {
    size_t references;
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

intptr_t vmm_map(vmm_t *vmm, uintptr_t hint, size_t size, unsigned flags);
int vmm_remap(vmm_t *vmm, uintptr_t address, size_t size, unsigned flags);
intptr_t vmm_move(vmm_t *vmm, uintptr_t addr, size_t size, vmm_t *dest_vmm, uintptr_t dest_addr, size_t dest_size);
int vmm_unmap(vmm_t *vmm, uintptr_t address, size_t size);

// vmm must be locked!
vmm_region_t *vmm_get_region(vmm_t *vmm, uintptr_t address);

void vmm_ref(vmm_t *vmm);
void vmm_deref(vmm_t *vmm);
