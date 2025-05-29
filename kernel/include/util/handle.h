#pragma once

#include "cpu/cpudata.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "proc/mutex.h"
#include "util/list.h"
#include "util/object.h"
#include <hydrogen/handle.h>
#include <stdint.h>

#define HANDLE_FLAGS (HYDROGEN_HANDLE_CLONE_KEEP | HYDROGEN_HANDLE_EXEC_KEEP)
#define NS_ILL_FLAGS (HYDROGEN_HANDLE_CLONE_KEEP)

typedef struct {
    object_t *object;
    object_rights_t rights;
    uint32_t flags;
} handle_data_t;

typedef struct namespace {
    object_t base;
    handle_data_t **data;
    uint64_t *bitmap;
    size_t capacity;
    size_t count;
    size_t reserved;
    size_t alloc_start;
    list_t reserved_waiting;
    mutex_t update_lock;
}
namespace_t;

int namespace_create(namespace_t **out);
int namespace_clone(namespace_t **out, namespace_t *ns);
hydrogen_ret_t namespace_add(
    namespace_t *ns,
    object_rights_t ns_rights,
    int handle,
    object_t *object,
    object_rights_t rights,
    uint32_t flags
);
int namespace_remove(namespace_t *ns, int handle);
int namespace_resolve(handle_data_t *out, namespace_t *ns, int handle);
void namespace_handle_exec(namespace_t *ns);

int hnd_reserve(namespace_t *ns);
void hnd_unreserve(namespace_t *ns);
int hnd_alloc_reserved(
    namespace_t *ns,
    object_t *object,
    object_rights_t rights,
    uint32_t flags,
    handle_data_t *buffer
); // buffer must have been allocated with `vmalloc(sizeof(*buffer))`

static inline hydrogen_ret_t hnd_alloc(object_t *object, object_rights_t rights, uint32_t flags) {
    return namespace_add(
        current_thread->namespace,
        HYDROGEN_NAMESPACE_ADD,
        HYDROGEN_INVALID_HANDLE,
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
