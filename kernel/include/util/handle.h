#pragma once

#include "hydrogen/handle.h"
#include "thread/mutex.h"
#include "util/object.h"
#include <stdint.h>

typedef struct {
    object_t *object;
    uint64_t rights;
} handle_data_t;

typedef struct {
    object_t base;
    handle_data_t *data;
    uint64_t *bitmap;
    size_t capacity;
    size_t alloc_start;
    mutex_t lock;
} namespace_t;

int create_namespace_raw(namespace_t **out);

int create_handle(object_t *obj, uint64_t rights, hydrogen_handle_t *out);
int basic_resolve(hydrogen_handle_t handle, handle_data_t *out); // increases the ref count of the obj!
int resolve(hydrogen_handle_t handle, handle_data_t *out, bool (*pred)(object_t *obj), uint64_t rights);
int get_ns(hydrogen_handle_t handle, namespace_t **out, uint64_t rights);
