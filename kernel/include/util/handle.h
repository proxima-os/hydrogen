#pragma once

#include "hydrogen/error.h"
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
    size_t capacity;
    size_t alloc_start;
    mutex_t lock;
} namespace_t;

hydrogen_error_t create_namespace_raw(namespace_t **out);

hydrogen_error_t create_handle(object_t *obj, uint64_t rights, hydrogen_handle_t *out);
hydrogen_error_t basic_resolve(hydrogen_handle_t handle, handle_data_t *out); // increases the ref count of the obj!
hydrogen_error_t resolve(hydrogen_handle_t handle, handle_data_t *out, bool (*pred)(object_t *obj), uint64_t rights);
