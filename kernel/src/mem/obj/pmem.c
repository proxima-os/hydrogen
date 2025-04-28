#include "mem/obj/pmem.h"
#include "errno.h"
#include "hydrogen/memory.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/pmap.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "util/object.h"
#include "util/panic.h"
#include <stdint.h>

static void pmem_vm_obj_free(object_t *ptr) {
    pmem_vm_object_t *self = (pmem_vm_object_t *)ptr;
    vmfree(self, sizeof(*self));
}

static void pmem_vm_obj_post_map(vm_object_t *ptr, vm_region_t *region) {
    if ((region->flags & VM_PERM_MASK) && (region->flags & HYDROGEN_MEM_SHARED)) {
        pmem_vm_object_t *self = (pmem_vm_object_t *)ptr;
        if (region->offset >= self->size) return;

        uint64_t map_phys = self->addr + region->offset;
        uint64_t map_size = self->size - region->offset;
        uint64_t reg_size = region->tail - region->head + 1;
        if (map_size > reg_size) map_size = reg_size;

        pmap_map(&region->space->pmap, region->head, map_size, map_phys, region->flags);
    }
}

static int pmem_vm_obj_get_phys(vm_object_t *ptr, uint64_t *out, UNUSED vm_region_t *region, size_t offset) {
    pmem_vm_object_t *self = (pmem_vm_object_t *)ptr;
    if (unlikely(offset >= self->size)) return ENOENT;

    *out = self->addr + offset;
    return 0;
}

const vm_object_ops_t pmem_vm_object_ops = {
        .base =
                {
                        .free = pmem_vm_obj_free,
                },
        .post_map = pmem_vm_obj_post_map,
        .get_phys = pmem_vm_obj_get_phys,
};

void pmem_vm_obj_init(pmem_vm_object_t *obj, uint64_t addr, uint64_t size) {
    ASSERT(!((addr | size) & PAGE_MASK));
    vm_obj_init(&obj->base, &pmem_vm_object_ops);
    obj->addr = addr;
    obj->size = size;
}
