#pragma once

#include "mem/vmm.h"

int anon_mem_object_create(mem_object_t **out, size_t pages);
int anon_mem_object_resize(mem_object_t *obj, size_t pages);
