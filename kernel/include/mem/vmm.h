#pragma once

#include "mem/pmap.h"
#include "proc/mutex.h"
#include "util/list.h"
#include "util/object.h"
#include <hydrogen/memory.h>
#include <hydrogen/types.h>
#include <stddef.h>
#include <stdint.h>

#define VMM_PERM_FLAGS (HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE | HYDROGEN_MEM_EXEC)
#define VMM_REGION_FLAGS (VMM_PERM_FLAGS | HYDROGEN_MEM_LAZY_RESERVE | HYDROGEN_MEM_SHARED | HYDROGEN_MEM_TYPE_MASK)
#define VMM_MAP_FLAGS (VMM_REGION_FLAGS | HYDROGEN_MEM_EXACT | HYDROGEN_MEM_OVERWRITE)

struct dentry;
struct inode;

typedef struct mem_object mem_object_t;
typedef struct vmm_region vmm_region_t;
typedef struct vmm vmm_t;

typedef struct {
    object_ops_t base;
    bool mem_type_allowed;
    void (*post_map)(mem_object_t *self, vmm_t *vmm, uintptr_t head, uintptr_t tail, unsigned flags, uint64_t offset);
    // if lock_rcu is true, this function locks rcu without unlocking it.
    // this is done in such a way that the returned page stays valid until rcu is unlocked.
    hydrogen_ret_t (*get_page)(
        mem_object_t *self,
        vmm_region_t *region,
        uint64_t index,
        bool lock_rcu,
        bool write
    );
} mem_object_ops_t;

#define SHARED_VM_ID 0
#define ANON_OBJ_ID 0

struct mem_object {
    object_t base;
    uint64_t id;
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
    uint64_t offset;
    list_node_t object_node;
};

struct vmm {
    object_t base;
    uint64_t id;
    rmutex_t lock; // rmutex is used here for futexes: they need to be able to fault stuff in while holding the vmm lock
    pmap_t pmap;
    vmm_region_t *regtree;
    list_t regions;
    size_t num_mapped;
    size_t num_reserved;
    size_t num_tables;
    uintptr_t vdso_addr;

    struct dentry *path;
    struct inode *inode;
};

int vmm_create(vmm_t **out);
int vmm_clone(vmm_t **out, vmm_t *src);

// WARNING: This does not increase vmm's ref count! You must do that yourself.
vmm_t *vmm_switch(vmm_t *vmm);

hydrogen_ret_t vmm_map(
    vmm_t *vmm,
    uintptr_t hint,
    size_t size,
    unsigned flags,
    mem_object_t *object,
    object_rights_t rights,
    uint64_t offset
);
hydrogen_ret_t vmm_map_vdso(vmm_t *vmm);
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

// expects object->base.ops to be set
void mem_object_init(mem_object_t *object);

int mem_object_read(mem_object_t *object, void *buffer, size_t count, uint64_t position);
int mem_object_write(mem_object_t *object, const void *buffer, size_t count, uint64_t position);
