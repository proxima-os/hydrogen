#pragma once

#include "util/refcount.h"
#include <hydrogen/eventqueue.h>
#include <stdbool.h>
#include <stdint.h>

struct active_event;

typedef enum {
    OBJECT_VMM,
    OBJECT_MEMORY,
    OBJECT_THREAD,
    OBJECT_PROCESS,
    OBJECT_NAMESPACE,
    OBJECT_EVENT_QUEUE,
    OBJECT_FILE_DESCRIPTION,
    OBJECT_INTERRUPT,
} object_type_t;

typedef struct object object_t;

typedef struct {
    void (*free)(object_t *self);
    int (*event_add)(object_t *self, uint32_t rights, struct active_event *event);
    void (*event_del)(object_t *self, struct active_event *event);
} object_ops_t;

struct object {
    const object_ops_t *ops;
    refcnt_t references;
    object_type_t type;
};

typedef uint32_t object_rights_t;

// expects object->ops to be set
void obj_init(object_t *object, object_type_t type);

static inline void obj_ref(object_t *object) {
    ref_inc(&object->references);
}

static inline void obj_deref(object_t *object) {
    if (ref_dec_maybe(&object->references)) {
        object->ops->free(object);
    }
}
