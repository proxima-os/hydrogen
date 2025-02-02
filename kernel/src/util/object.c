#include "util/object.h"

void obj_init(object_t *obj, const object_ops_t *ops) {
    obj->ops = ops;
    obj->references = 1;
}

void obj_ref(object_t *obj) {
    __atomic_fetch_add(&obj->references, 1, __ATOMIC_ACQUIRE);
}

void obj_deref(object_t *obj) {
    if (__atomic_fetch_sub(&obj->references, 1, __ATOMIC_ACQ_REL) == 1) {
        obj->ops->free(obj);
    }
}
