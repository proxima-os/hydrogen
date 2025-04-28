#include "util/handle.h"
#include "cpu/cpu.h"
#include "errno.h"
#include "hydrogen/handle.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "thread/mutex.h"
#include "util/object.h"
#include <stdint.h>

#define HANDLE_BITS 31
#define MAX_HANDLE (1ul << HANDLE_BITS)
#define HANDLE_MASK (MAX_HANDLE - 1)

static hydrogen_handle_t idx_to_handle(size_t idx) {
    // this is done to make it harder for userspace to accidentally treat handles as pointers
    // (since the addresses will be in kernel space)
    return (hydrogen_handle_t)(-(uintptr_t)idx - PAGE_SIZE);
}

static size_t handle_to_idx(hydrogen_handle_t handle) {
    return -((uintptr_t)handle + PAGE_SIZE);
}

static void namespace_free(object_t *ptr) {
    namespace_t *ns = (namespace_t *)ptr;

    for (size_t i = 0; i < ns->capacity; i++) {
        handle_data_t *data = &ns->data[i];

        if (data->object) {
            obj_deref(data->object);
        }
    }

    vmfree(ns->data, ns->capacity * sizeof(*ns->data));
    vmfree(ns, sizeof(*ns));
}

static const object_ops_t namespace_ops = {.free = namespace_free};

int create_namespace_raw(namespace_t **out) {
    namespace_t *ns = vmalloc(sizeof(*ns));
    if (unlikely(!ns)) return ENOMEM;
    memset(ns, 0, sizeof(*ns));

    obj_init(&ns->base, &namespace_ops);

    *out = ns;
    return 0;
}

static int do_create(namespace_t *ns, object_t *obj, uint64_t rights, hydrogen_handle_t *out) {
    mutex_lock(&ns->lock);

    size_t i = ns->alloc_start;

    while (i < ns->capacity) {
        if (!ns->data[i].object) goto success;
        i += 1;
    }

    // No free handles in current buffer, expand

    size_t new_cap = ns->capacity ? ns->capacity * 2 : 8;
    if (unlikely(new_cap > MAX_HANDLE)) goto fail;

    handle_data_t *new_buf = vmalloc(sizeof(*new_buf) * new_cap);
    if (unlikely(!new_buf)) goto fail;
    memcpy(new_buf, ns->data, ns->capacity * sizeof(*new_buf));
    memset(&new_buf[ns->capacity], 0, (new_cap - ns->capacity) * sizeof(*new_buf));
    vmfree(ns->data, ns->capacity * sizeof(*new_buf));
    ns->data = new_buf;
    ns->capacity = new_cap;

success:
    ns->alloc_start = i + 1;

    obj_ref(obj);
    ns->data[i].object = obj;
    ns->data[i].rights = rights;

    mutex_unlock(&ns->lock);
    *out = idx_to_handle(i);
    return 0;

fail:
    mutex_unlock(&ns->lock);
    return ENOMEM;
}

int create_handle(object_t *obj, uint64_t rights, hydrogen_handle_t *out) {
    return do_create(current_thread->namespace, obj, rights, out);
}

int basic_resolve(hydrogen_handle_t handle, handle_data_t *out) {
    if (unlikely(!handle)) return EBADF;

    size_t idx = handle_to_idx(handle);
    if (unlikely(idx >= MAX_HANDLE)) return EBADF;

    namespace_t *ns = current_thread->namespace;
    mutex_lock(&ns->lock);

    if (unlikely(idx >= ns->capacity) || unlikely(!ns->data[idx].object)) {
        mutex_unlock(&ns->lock);
        return EBADF;
    }

    *out = ns->data[idx];
    obj_ref(out->object);
    mutex_unlock(&ns->lock);
    return 0;
}

int resolve(hydrogen_handle_t handle, handle_data_t *out, bool (*pred)(object_t *obj), uint64_t rights) {
    handle_data_t data;
    int error = basic_resolve(handle, &data);
    if (unlikely(error)) return error;

    if (!pred(data.object)) {
        obj_deref(data.object);
        return EBADF;
    }

    if ((data.rights & rights) != rights) {
        obj_deref(data.object);
        return EBADF;
    }

    if (out) *out = data;
    return 0;
}

hydrogen_ret_t hydrogen_namespace_create(void) {
    namespace_t *ns;
    int error = create_namespace_raw(&ns);
    if (unlikely(error)) return RET_ERROR(error);

    hydrogen_handle_t handle;
    error = create_handle(&ns->base, -1, &handle);
    obj_deref(&ns->base);
    return RET_HANDLE_MAYBE(error, handle);
}

static bool is_namespace(object_t *obj) {
    return obj->ops == &namespace_ops;
}

static int get_ns(hydrogen_handle_t handle, namespace_t **out, uint64_t rights) {
    if (handle) {
        handle_data_t data;
        int error = resolve(handle, &data, is_namespace, rights);
        if (unlikely(error)) return error;
        *out = (namespace_t *)data.object;
    } else {
        *out = current_thread->namespace;
    }

    return 0;
}

hydrogen_ret_t hydrogen_handle_create(
        hydrogen_handle_t namespace,
        hydrogen_handle_t object,
        uint64_t rights
) {
    namespace_t *ns;
    int error = get_ns(namespace, &ns, HYDROGEN_NAMESPACE_RIGHT_CREATE);
    if (unlikely(error)) return RET_ERROR(error);

    handle_data_t data;
    error = basic_resolve(object, &data);
    if (unlikely(error)) {
        if (namespace) obj_deref(&ns->base);
        return RET_ERROR(error);
    }

    hydrogen_handle_t handle;

    if (!is_namespace(data.object)) {
        error = do_create(ns, data.object, rights & data.rights, &handle);
    } else {
        error = EINVAL;
    }

    obj_deref(data.object);
    if (namespace) obj_deref(&ns->base);
    return RET_HANDLE_MAYBE(error, handle);
}

int hydrogen_handle_close(hydrogen_handle_t namespace, hydrogen_handle_t handle) {
    if (unlikely(!handle)) return EBADF;

    size_t idx = handle_to_idx(handle);
    if (unlikely(idx >= MAX_HANDLE)) return EBADF;

    namespace_t *ns;
    int error = get_ns(namespace, &ns, HYDROGEN_NAMESPACE_RIGHT_CLOSE);
    if (unlikely(error)) return error;
    error = EBADF;

    mutex_lock(&ns->lock);

    if (idx >= ns->capacity || !ns->data[idx].object) goto fail;

    obj_deref(ns->data[idx].object);
    ns->data[idx].object = NULL;

    if (idx < ns->alloc_start) ns->alloc_start = idx;

    error = 0;
fail:
    mutex_unlock(&ns->lock);
    if (namespace) obj_deref(&ns->base);
    return error;
}
