#pragma once

#include "util/handle.h"

#define THIS_NAMESPACE_RIGHTS \
    (HYDROGEN_NAMESPACE_RESOLVE | HYDROGEN_NAMESPACE_REMOVE | HYDROGEN_NAMESPACE_ADD | HYDROGEN_NAMESPACE_CLONE)

static inline int namespace_or_this(namespace_t **out, int handle, object_rights_t rights) {
    if (handle == HYDROGEN_THIS_NAMESPACE) {
        *out = current_thread->namespace;
        return 0;
    }

    handle_data_t data;
    int error = hnd_resolve(&data, handle, OBJECT_NAMESPACE, rights);
    if (unlikely(error)) return error;

    *out = (namespace_t *)data.object;
    return 0;
}
