#pragma once

#include "util/refcount.h"
#include <stdint.h>

typedef enum {
    OBJECT_VMM,
    OBJECT_MEMORY,
    OBJECT_THREAD,
    OBJECT_PROCESS,
} object_type_t;

typedef struct object object_t;

typedef struct {
    void (*free)(object_t *self);
} object_ops_t;

struct object {
    const object_ops_t *ops;
    refcnt_t references;
    object_type_t type;
};

typedef uint32_t object_rights_t;

// expects object->ops to be set
void obj_init(object_t *object, object_type_t type);

static inline void obj_ref_n(object_t *object, size_t num) {
    ref_add(&object->references, num);
}

static inline void obj_deref_n(object_t *object, size_t num) {
    if (ref_sub(&object->references, num)) {
        object->ops->free(object);
    }
}

static inline void obj_ref(object_t *object) {
    obj_ref_n(object, 1);
}

static inline void obj_deref(object_t *object) {
    obj_deref_n(object, 1);
}
