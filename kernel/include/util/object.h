#pragma once

#include <stddef.h>

typedef struct object object_t;

typedef struct {
    void (*free)(object_t *self);
} object_ops_t;

struct object {
    const object_ops_t *ops; // also used to identify the object type
    size_t references;
};

void obj_init(object_t *obj, const object_ops_t *ops);

void obj_ref(object_t *obj);
void obj_deref(object_t *obj);
