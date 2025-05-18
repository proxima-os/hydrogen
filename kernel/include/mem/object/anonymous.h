#pragma once

#include "mem/vmm.h"

typedef struct {
    mem_object_t base;
    uintptr_t root;
    size_t count;
    size_t tables;
    mutex_t update_lock;
} anon_mem_object_t;

int anon_mem_object_init(anon_mem_object_t *obj, size_t pages);
int anon_mem_object_create(mem_object_t **out, size_t pages);
int anon_mem_object_resize(mem_object_t *obj, size_t pages);
bool is_anon_mem_object(mem_object_t *obj);
