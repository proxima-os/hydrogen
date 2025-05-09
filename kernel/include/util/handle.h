#pragma once

#include "cpu/cpudata.h"
#include "errno.h"
#include "hydrogen/handle.h"
#include "kernel/compiler.h"
#include "proc/mutex.h"
#include "util/object.h"
#include <stdint.h>

#define HANDLE_FLAGS (HYDROGEN_HANDLE_CLONE_KEEP)
#define NS_ILL_FLAGS (HYDROGEN_HANDLE_CLONE_KEEP)

typedef struct {
    object_t *object;
    object_rights_t rights;
    uint16_t flags;
} handle_data_t;

typedef struct namespace {
    object_t base;
    handle_data_t **data;
    uint64_t *bitmap;
    size_t capacity;
    size_t alloc_start;
    mutex_t update_lock;
}
namespace_t;

int namespace_create(namespace_t **out);
int namespace_clone(namespace_t **out, namespace_t *ns);
int namespace_add(
        namespace_t *ns,
        object_rights_t ns_rights,
        int handle,
        object_t *object,
        object_rights_t rights,
        uint32_t flags
);
int namespace_remove(namespace_t *ns, int handle);
int namespace_resolve(handle_data_t *out, namespace_t *ns, int handle);

static inline int hnd_alloc(object_t *object, object_rights_t rights, uint32_t flags) {
    return namespace_add(
            current_thread->namespace,
            HYDROGEN_NAMESPACE_ADD,
            HYDROGEN_FREE_HANDLE,
            object,
            rights,
            flags
    );
}

static inline int hnd_resolve(handle_data_t *out, int handle, object_type_t type, object_rights_t rights) {
    int error = namespace_resolve(out, current_thread->namespace, handle);
    if (unlikely(error)) return error;

    if (unlikely(out->object->type != type) || unlikely((out->rights & rights) != rights)) {
        obj_deref(out->object);
        return EBADF;
    }

    return 0;
}
