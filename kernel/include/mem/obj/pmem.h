#pragma once

#include "mem/vmm.h"
#include <stdint.h>

typedef struct {
    vm_object_t base;
    uint64_t addr;
    uint64_t size;
} pmem_vm_object_t;

extern const vm_object_ops_t pmem_vm_object_ops;

void pmem_vm_obj_init(pmem_vm_object_t *obj, uint64_t addr, uint64_t size);
