#include "util/handle.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "proc/mutex.h"
#include "proc/rcu.h"
#include "proc/sched.h"
#include "string.h"
#include "util/list.h"
#include "util/object.h"
#include <hydrogen/handle.h>
#include <hydrogen/types.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

static size_t get_map_offset(size_t capacity) {
    return (capacity * sizeof(handle_data_t) + (_Alignof(uint64_t) - 1)) & ~(_Alignof(uint64_t) - 1);
}

static size_t get_map_size(size_t capacity) {
    return (capacity + 63) / 64 * sizeof(uint64_t);
}

static size_t get_buffer_size(size_t capacity) {
    return get_map_offset(capacity) + get_map_size(capacity);
}

static void namespace_free(object_t *ptr) {
    namespace_t *self = (namespace_t *)ptr;

    uint64_t *bitmap = self->bitmap;

    for (size_t i = 0; i < self->capacity; i += 64) {
        uint64_t value = *bitmap++;
        if (!value) continue;

        handle_data_t **data = &self->data[i];

        do {
            size_t extra = __builtin_ctzll(value);
            data += extra;
            value >>= extra;

            obj_deref(data[0]->object);
            vfree(data[0], sizeof(*data[0]));

            value &= ~1ull;
        } while (value != 0);
    }

    vfree(self->data, get_buffer_size(self->capacity));
    vfree(self, sizeof(*self));
}

static const object_ops_t namespace_ops = {.free = namespace_free};

int namespace_create(namespace_t **out) {
    namespace_t *ns = vmalloc(sizeof(*ns));
    if (unlikely(!ns)) return ENOMEM;
    memset(ns, 0, sizeof(*ns));

    ns->base.ops = &namespace_ops;
    obj_init(&ns->base, OBJECT_NAMESPACE);

    *out = ns;
    return 0;
}

static int expand(namespace_t *ns, size_t min_capacity) {
    if (min_capacity <= ns->capacity) return 0;
    if (min_capacity < 2) min_capacity = 2;

    size_t new_cap = 1ul << ((sizeof(long) * 8) - __builtin_clzl(min_capacity - 1));
    size_t map_offs = get_map_offset(new_cap);
    size_t map_size = get_map_size(new_cap);
    size_t buf_size = map_offs + map_size;
    void *buffer = vmalloc(buf_size);
    if (unlikely(!buffer)) return 0;

    handle_data_t **old_data = ns->data;
    handle_data_t **new_data = buffer;
    size_t old_map_offs = get_map_offset(ns->capacity);
    memcpy(new_data, old_data, old_map_offs);
    memset((void *)new_data + old_map_offs, 0, map_offs - old_map_offs);

    size_t old_map_size = get_map_size(ns->capacity);
    uint64_t *new_bitmap = buffer + map_offs;
    memcpy(new_bitmap, ns->bitmap, old_map_size);
    memset((void *)new_bitmap + old_map_size, 0, map_size - old_map_size);

    ns->bitmap = new_bitmap;
    rcu_write(ns->data, new_data);
    __atomic_store_n(&ns->capacity, new_cap, __ATOMIC_RELEASE);
    rcu_sync();
    vfree(old_data, old_map_offs + old_map_size);
    return 0;
}

int namespace_clone(namespace_t **out, namespace_t *ns) {
    namespace_t *dst;
    int error = namespace_create(&dst);
    if (unlikely(error)) return error;

    mutex_acq(&ns->update_lock, 0, false);

    size_t capacity = (ns->capacity + 63) & ~63;
    uint64_t *bitmap = &ns->bitmap[capacity / 64];

    // Figure out the capacity
    while (capacity > 0) {
        uint64_t value = *--bitmap;

        if (value != 0) {
            handle_data_t **data = &ns->data[capacity - 1];

            do {
                size_t extra = __builtin_clzll(value);
                capacity -= extra;
                data -= extra;
                value <<= extra;

                if ((data[0]->flags & HYDROGEN_HANDLE_CLONE_KEEP) != 0) {
                    break;
                }

                value &= ~(1ull << 63);
            } while (value != 0);

            if (value != 0) break;
            capacity &= ~63;
        } else {
            capacity -= 64;
        }
    }

    if (capacity != 0) {
        // Create the buffer
        error = expand(dst, capacity);

        if (unlikely(error)) {
            mutex_rel(&ns->update_lock);
            obj_deref(&dst->base);
            return error;
        }

        bitmap = ns->bitmap;
        uint64_t *dbitmap = dst->bitmap;
        dst->alloc_start = capacity;

        // Clone the handles
        for (size_t i = 0; i < capacity; i += 64) {
            uint64_t value = *bitmap++;

            if (value == 0) {
                if (dst->alloc_start == capacity) dst->alloc_start = i;
                dbitmap++;
                continue;
            }

            handle_data_t **sdata = &ns->data[i];
            handle_data_t **ddata = &dst->data[i];
            uint64_t mask = 1;

            do {
                size_t extra = __builtin_ctzll(value);
                sdata += extra;
                ddata += extra;
                value >>= extra;
                mask <<= extra;

                if ((sdata[0]->flags & HYDROGEN_HANDLE_CLONE_KEEP) != 0) {
                    handle_data_t *new_data = vmalloc(sizeof(*new_data));

                    if (unlikely(!new_data)) {
                        mutex_rel(&ns->update_lock);
                        obj_deref(&dst->base);
                        return ENOMEM;
                    }

                    memcpy(new_data, sdata[0], sizeof(*sdata[0]));
                    obj_ref(new_data->object);
                    dst->count += 1;

                    *ddata = new_data;
                    *dbitmap |= mask;
                }

                value &= ~1ull;
            } while (value != 0);

            if (dst->alloc_start == capacity && *dbitmap != UINT64_MAX) {
                dst->alloc_start = i + __builtin_ctzll(~*dbitmap);
            }

            dbitmap += 1;
        }
    }

    mutex_rel(&ns->update_lock);
    *out = dst;
    return 0;
}

static size_t get_free_idx(namespace_t *ns, size_t minimum) {
    size_t idx = ns->alloc_start;
    if (idx < minimum) idx = minimum;

    uint64_t *bitmap = &ns->bitmap[idx / 64];
    size_t offset = idx % 64;
    idx &= ~63;

    while (idx < ns->capacity) {
        uint64_t value = *bitmap >> offset;

        if (value != UINT64_MAX) {
            idx += __builtin_ctzll(~value) + offset;
            break;
        }

        idx += 64;
        bitmap += 1;
        offset = 0;
    }

    return idx;
}

static hydrogen_ret_t get_next_handle(namespace_t *ns, size_t minimum) {
again: {
    size_t idx = get_free_idx(ns, minimum);
    if (idx > (size_t)INT_MAX) return ret_error(EMFILE);

    if (idx >= ns->capacity || ns->capacity - ns->count - ns->reserved == 0) {
        size_t min = ns->capacity + 1;
        if (min <= idx) min = idx + 1;

        if (min > (size_t)INT_MAX + 1) {
            // This can only happen if some slots are reserved. They might be unreserved instead of allocated;
            // wait until reserved count drops to 0 so that we can be sure there are no handles available.
            sched_prepare_wait(false);
            list_insert_tail(&ns->reserved_waiting, &current_thread->wait_node);
            mutex_rel(&ns->update_lock);
            sched_perform_wait(0);
            mutex_acq(&ns->update_lock, 0, false);
            list_remove(&ns->reserved_waiting, &current_thread->wait_node);
            goto again;
        }

        int error = expand(ns, min);
        if (unlikely(error)) return ret_error(error);
    }

    return ret_integer(idx);
}
}

static void associate_handle(namespace_t *ns, int handle, handle_data_t *data) {
    ns->bitmap[handle / 64] |= 1ull << (handle % 64);
    if ((size_t)handle == ns->alloc_start) ns->alloc_start = handle + 1;

    obj_ref(data->object);
    rcu_write(ns->data[handle], data);
}

hydrogen_ret_t namespace_add(
    namespace_t *ns,
    object_rights_t ns_rights,
    int handle,
    object_t *object,
    object_rights_t rights,
    uint32_t flags
) {
    ASSERT((flags & ~HANDLE_FLAGS) == 0);
    ASSERT(object->type != OBJECT_NAMESPACE || (flags & NS_ILL_FLAGS) == 0);

    handle_data_t *new_data = vmalloc(sizeof(*new_data));
    if (unlikely(!new_data)) return ret_error(ENOMEM);
    memset(new_data, 0, sizeof(*new_data));
    new_data->object = object;
    new_data->rights = rights;
    new_data->flags = flags;

    mutex_acq(&ns->update_lock, 0, false);

    handle_data_t *old_data;

    if (handle < 0) {
        hydrogen_ret_t ret = get_next_handle(ns, -(handle + 1));

        if (unlikely(ret.error)) {
            mutex_rel(&ns->update_lock);
            vfree(new_data, sizeof(*new_data));
            return ret;
        }

        handle = ret.integer;
        old_data = NULL;
    } else if ((size_t)handle < ns->capacity) {
        old_data = ns->data[handle];

        if (old_data != NULL && (ns_rights & HYDROGEN_NAMESPACE_REMOVE) == 0) {
            mutex_rel(&ns->update_lock);
            vfree(new_data, sizeof(*new_data));
            return ret_error(EBADF);
        }
    } else {
        int error = expand(ns, (size_t)handle + 1);

        if (unlikely(error)) {
            mutex_rel(&ns->update_lock);
            vfree(new_data, sizeof(*new_data));
            return ret_error(error);
        }

        old_data = NULL;
    }

    associate_handle(ns, handle, new_data);
    if (old_data == NULL) ns->count += 1;
    mutex_rel(&ns->update_lock);

    if (old_data != NULL) {
        rcu_sync();
        obj_deref(old_data->object);
        vfree(old_data, sizeof(*old_data));
    }

    return ret_integer(handle);
}

int hnd_reserve(namespace_t *ns) {
    mutex_acq(&ns->update_lock, 0, false);

    if (ns->count + ns->reserved >= ns->capacity) {
        int error = expand(ns, ns->capacity + 1);
        if (unlikely(error)) {
            mutex_rel(&ns->update_lock);
            return error;
        }
    }

    ns->reserved += 1;
    mutex_rel(&ns->update_lock);
    return 0;
}

static void wake_reserved_waiter(namespace_t *ns) {
    LIST_FOREACH(ns->reserved_waiting, thread_t, wait_node, thread) {
        if (sched_wake(thread)) break;
    }
}

void hnd_unreserve(namespace_t *ns) {
    mutex_acq(&ns->update_lock, 0, false);

    ns->reserved -= 1;
    if (ns->reserved == 0) wake_reserved_waiter(ns);

    mutex_rel(&ns->update_lock);
}

int hnd_alloc_reserved(
    namespace_t *ns,
    object_t *object,
    object_rights_t rights,
    uint32_t flags,
    handle_data_t *buffer
) {
    memset(buffer, 0, sizeof(*buffer));
    buffer->object = object;
    buffer->rights = rights;
    buffer->flags = flags;

    mutex_acq(&ns->update_lock, 0, false);

    ASSERT(ns->reserved > 0);

    size_t handle = get_free_idx(ns, 0);
    ASSERT(handle < ns->capacity);

    associate_handle(ns, handle, buffer);
    ns->count += 1;
    ns->reserved -= 1;
    if (ns->reserved == 0) wake_reserved_waiter(ns);

    mutex_rel(&ns->update_lock);
    // no rcu_sync necessary, as there is no old data for us to free
    return handle;
}

int namespace_remove(namespace_t *ns, int handle) {
    ASSERT(handle >= 0);
    mutex_acq(&ns->update_lock, 0, false);

    if (unlikely((size_t)handle >= ns->capacity)) {
        mutex_rel(&ns->update_lock);
        return EBADF;
    }

    handle_data_t *data = ns->data[handle];

    if (unlikely(!data)) {
        mutex_rel(&ns->update_lock);
        return EBADF;
    }

    rcu_write(ns->data[handle], NULL);
    ns->bitmap[handle / 64] &= ~(1ull << (handle % 64));
    if ((size_t)handle < ns->alloc_start) ns->alloc_start = handle;
    ns->count -= 1;

    mutex_rel(&ns->update_lock);
    rcu_sync();
    obj_deref(data->object);
    vfree(data, sizeof(*data));
    return 0;
}

int namespace_resolve(handle_data_t *out, namespace_t *ns, int handle) {
    if (unlikely(handle < 0)) return EBADF;
    // the handle table cannot shrink, only grow
    if (unlikely((size_t)handle >= __atomic_load_n(&ns->capacity, __ATOMIC_ACQUIRE))) return EBADF;

    rcu_read_lock();
    handle_data_t *data = rcu_read(rcu_read(ns->data)[handle]);

    if (likely(data != NULL)) {
        *out = *data;
        obj_ref(out->object);
    }

    rcu_read_unlock();
    return likely(data != NULL) ? 0 : EBADF;
}

void namespace_handle_exec(namespace_t *ns) {
    mutex_acq(&ns->update_lock, 0, false);
    ASSERT(ns->reserved == 0);

    uint64_t *bitmap = ns->bitmap;

    for (size_t i = 0; i < ns->capacity; i += 64) {
        uint64_t bmval = *bitmap++;
        if (!bmval) continue;

        handle_data_t **data = &ns->data[i];
        uint64_t mask = 1;

        do {
            size_t extra = __builtin_ctzll(bmval);
            bmval >>= extra;
            mask <<= extra;
            data += extra;

            handle_data_t *cur = *data;

            if ((cur->flags & HYDROGEN_HANDLE_EXEC_KEEP) == 0) {
                rcu_write(*data, NULL);
                bitmap[-1] &= ~mask;
                rcu_sync();
                obj_deref(cur->object);
                vfree(cur, sizeof(*cur));
            }

            bmval &= ~1ull;
        } while (bmval);
    }

    mutex_rel(&ns->update_lock);
}
