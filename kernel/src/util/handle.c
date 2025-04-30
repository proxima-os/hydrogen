#include "util/handle.h"
#include "cpu/cpu.h"
#include "errno.h"
#include "hydrogen/handle.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "thread/mutex.h"
#include "util/object.h"
#include "util/panic.h"
#include <stdint.h>

static hydrogen_handle_t idx_to_handle(size_t idx) {
    return (hydrogen_handle_t)(idx + 1);
}

static size_t handle_to_idx(hydrogen_handle_t handle) {
    return (size_t)handle - 1;
}

static size_t bitmap_entries(size_t capacity) {
    return (capacity + 63) / 64;
}

static void free_buffer(namespace_t *ns) {
    vmfree(ns->data, (ns->capacity * sizeof(*ns->data)) + (bitmap_entries(ns->capacity) * sizeof(*ns->bitmap)));
}

static void namespace_free(object_t *ptr) {
    namespace_t *ns = (namespace_t *)ptr;

    for (size_t i = 0; i < ns->capacity; i += 64) {
        uint64_t value = ns->bitmap[i / 64];

        while (value) {
            size_t j = __builtin_ffsl(value) - 1;
            value &= ~(1ul << j);
            obj_deref(ns->data[i + j].object);
        }
    }

    free_buffer(ns);
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

static bool expand_buffer(namespace_t *ns, size_t new_cap) {
    size_t bitmap_len = bitmap_entries(new_cap);
    handle_data_t *data = vmalloc((new_cap * sizeof(*ns->data)) + (bitmap_len * sizeof(*ns->bitmap)));
    if (unlikely(!data)) return false;
    uint64_t *bitmap = (void *)data + new_cap * sizeof(*data);

    size_t old_bitmap_len = bitmap_entries(ns->capacity);
    memcpy(data, ns->data, ns->capacity * sizeof(*data));
    memcpy(bitmap, ns->bitmap, old_bitmap_len * sizeof(*bitmap));
    memset(bitmap + old_bitmap_len, 0, (bitmap_len - old_bitmap_len) * sizeof(*bitmap));

    free_buffer(ns);
    ns->data = data;
    ns->bitmap = bitmap;
    ns->capacity = new_cap;
    return true;
}

static int do_create(namespace_t *ns, object_t *obj, uint64_t rights, hydrogen_handle_t *out) {
    mutex_lock(&ns->lock);

    size_t i = ns->alloc_start & ~63;
    size_t j = 0;

    while (i < ns->capacity) {
        uint64_t value = ns->bitmap[i / 64];

        if (value != UINT64_MAX) {
            if (value != 0) {
                j = __builtin_ctzl(~value);
            } else {
                j = 0;
            }

            i += j;
            if (i < ns->capacity) goto success;
        } else {
            i += 64;
        }
    }

    // No free handles in current buffer, expand

    if (unlikely(!expand_buffer(ns, ns->capacity ? ns->capacity * 2 : 8))) goto fail;

success:
    ns->alloc_start = i + 1;

    obj_ref(obj);
    ns->bitmap[i / 64] |= 1ul << j;
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

static bool is_idx_valid(namespace_t *ns, size_t idx) {
    return idx < ns->capacity && (ns->bitmap[idx / 64] & (1ul << (idx % 64))) != 0;
}

static int resolve_in_ns(namespace_t *ns, hydrogen_handle_t handle, handle_data_t *out) {
    ASSERT(handle != NULL);

    size_t idx = handle_to_idx(handle);
    mutex_lock(&ns->lock);

    if (unlikely(!is_idx_valid(ns, idx))) {
        mutex_unlock(&ns->lock);
        return EBADF;
    }

    *out = ns->data[idx];
    obj_ref(out->object);
    mutex_unlock(&ns->lock);
    return 0;
}

int basic_resolve(hydrogen_handle_t handle, handle_data_t *out) {
    if (unlikely(!handle)) return EBADF;
    return resolve_in_ns(current_thread->namespace, handle, out);
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

static size_t next_power_of_two(size_t value) {
    if (!(value & (value - 1))) return value;

    return 1ul << (64 - __builtin_clzl(value - 1));
}

static bool is_namespace(object_t *obj) {
    return obj->ops == &namespace_ops;
}

hydrogen_ret_t hydrogen_namespace_clone(hydrogen_handle_t namespace) {
    namespace_t *src;
    int error = get_ns(namespace, &src, HYDROGEN_NAMESPACE_RIGHT_CLONE);
    if (unlikely(error)) return RET_ERROR(error);

    namespace_t *ns;
    error = create_namespace_raw(&ns);
    if (unlikely(error)) {
        if (namespace) obj_deref(&src->base);
        return RET_ERROR(error);
    }

    mutex_lock(&src->lock);

    size_t max = (src->capacity + 63) & ~63;
    uint64_t *sbmap = &src->bitmap[max / 64];

    while (max > 0) {
        uint64_t bmval = *--sbmap;

        if (bmval) {
            size_t i = 0;
            handle_data_t *data = &src->data[max];

            while (i < 64) {
                data--;
                if (data->object && !is_namespace(data->object)) break;
                i += 1;
            }

            if (i != 64) break;
        }

        max -= 64;
    }

    if (!max) goto ret;

    if (unlikely(!expand_buffer(ns, next_power_of_two(max)))) {
        error = ENOMEM;
        goto ret;
    }

    sbmap = src->bitmap;
    uint64_t *dbmap = ns->bitmap;

    ns->alloc_start = max;

    for (size_t i = 0; i < max; i += 64) {
        uint64_t sbmval = *sbmap++;
        if (!sbmval) continue;

        uint64_t dbmval = 0;

        while (sbmval) {
            size_t j = __builtin_ffsl(sbmval) - 1;
            sbmval &= ~(1ul << j);

            size_t idx = i + j;
            handle_data_t data = src->data[idx];
            if (is_namespace(data.object)) continue;

            ns->data[idx] = data;
            obj_ref(data.object);
            dbmval |= 1ul << j;
        }

        if (dbmval != 0 && dbmval != UINT64_MAX && ns->alloc_start == max) {
            ns->alloc_start = i + __builtin_ffsl(~sbmval) - 1;
        }

        *dbmap++ = dbmval;
    }

ret:
    mutex_unlock(&src->lock);
    if (namespace) obj_deref(&src->base);

    hydrogen_handle_t handle;
    if (likely(!error)) error = create_handle(&ns->base, -1, &handle);
    obj_deref(&ns->base);

    return RET_HANDLE_MAYBE(error, handle);
}

int get_ns(hydrogen_handle_t handle, namespace_t **out, uint64_t rights) {
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
        hydrogen_handle_t source_ns,
        hydrogen_handle_t object,
        uint64_t rights
) {
    if (unlikely(!object)) return RET_ERROR(EBADF);

    namespace_t *ns;
    int error = get_ns(namespace, &ns, HYDROGEN_NAMESPACE_RIGHT_CREATE);
    if (unlikely(error)) return RET_ERROR(error);

    namespace_t *src;
    error = get_ns(source_ns, &src, HYDROGEN_NAMESPACE_RIGHT_RESOLVE);
    if (unlikely(error)) {
        if (namespace) obj_deref(&ns->base);
        return RET_ERROR(error);
    }

    handle_data_t data;
    error = resolve_in_ns(src, object, &data);
    if (unlikely(error)) {
        if (source_ns) obj_deref(&src->base);
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
    if (source_ns) obj_deref(&src->base);
    if (namespace) obj_deref(&ns->base);
    return RET_HANDLE_MAYBE(error, handle);
}

int hydrogen_handle_close(hydrogen_handle_t namespace, hydrogen_handle_t handle) {
    if (unlikely(!handle)) return EBADF;

    size_t idx = handle_to_idx(handle);

    namespace_t *ns;
    int error = get_ns(namespace, &ns, HYDROGEN_NAMESPACE_RIGHT_CLOSE);
    if (unlikely(error)) return error;
    error = EBADF;

    mutex_lock(&ns->lock);

    if (unlikely(!is_idx_valid(ns, idx))) goto fail;

    obj_deref(ns->data[idx].object);
    ns->data[idx].object = NULL;
    ns->bitmap[idx / 64] &= ~(1ul << (idx % 64));

    if (idx < ns->alloc_start) ns->alloc_start = idx;

    error = 0;
fail:
    mutex_unlock(&ns->lock);
    if (namespace) obj_deref(&ns->base);
    return error;
}
