#include "util/object.h"
#include "util/refcount.h"

void obj_init(object_t *object, object_type_t type) {
    object->references = REF_INIT(1);
    object->type = type;
}
