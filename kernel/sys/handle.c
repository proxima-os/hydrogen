#include "hydrogen/handle.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "sys/handle.h"
#include "util/handle.h"
#include "util/object.h"
#include <stdint.h>

#define NAMESPACE_RIGHTS THIS_NAMESPACE_RIGHTS

hydrogen_ret_t hydrogen_namespace_create(uint32_t flags) {
    if (unlikely((flags & ~(HANDLE_FLAGS & ~NS_ILL_FLAGS)) != 0)) return ret_error(EINVAL);

    namespace_t *ns;
    int error = namespace_create(&ns);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = hnd_alloc(&ns->base, NAMESPACE_RIGHTS, flags);
    obj_deref(&ns->base);
    return ret;
}

hydrogen_ret_t hydrogen_namespace_clone(int ns_hnd, uint32_t flags) {
    if (unlikely((flags & ~(HANDLE_FLAGS & ~NS_ILL_FLAGS)) != 0)) return ret_error(EINVAL);

    namespace_t *src;
    int error = namespace_or_this(&src, ns_hnd, HYDROGEN_NAMESPACE_CLONE);
    if (unlikely(error)) return ret_error(error);

    namespace_t *ns;
    error = namespace_clone(&ns, src);
    if (unlikely(error)) goto err;

    hydrogen_ret_t ret = hnd_alloc(&ns->base, NAMESPACE_RIGHTS, flags);
    obj_deref(&ns->base);
    if (ns_hnd != HYDROGEN_THIS_NAMESPACE) obj_deref(&src->base);
    return ret;
err:
    if (ns_hnd != HYDROGEN_THIS_NAMESPACE) obj_deref(&src->base);
    return ret_error(error);
}

hydrogen_ret_t hydrogen_namespace_add(
        int src_ns_hnd,
        int src_obj_hnd,
        int dst_ns_hnd,
        int dst_hnd,
        uint32_t rights,
        uint32_t flags
) {
    if (unlikely(src_obj_hnd < 0)) return ret_error(EBADF);
    if (dst_ns_hnd < 0 && unlikely(dst_hnd != HYDROGEN_THIS_NAMESPACE)) return ret_error(EINVAL);
    if (dst_hnd < 0 && unlikely(dst_hnd != HYDROGEN_INVALID_HANDLE)) return ret_error(EINVAL);

    int flags_mode = flags & (3u << 30);
    flags &= ~flags_mode;

    namespace_t *src_ns;
    int error = namespace_or_this(&src_ns, src_ns_hnd, HYDROGEN_NAMESPACE_RESOLVE);
    if (unlikely(error)) return ret_error(error);

    namespace_t *dst_ns;
    object_rights_t dst_ns_rights;

    if (dst_ns_hnd == HYDROGEN_THIS_NAMESPACE) {
        dst_ns = current_thread->namespace;
        dst_ns_rights = NAMESPACE_RIGHTS;
    } else {
        handle_data_t data;
        error = hnd_resolve(&data, dst_ns_hnd, OBJECT_NAMESPACE, HYDROGEN_NAMESPACE_ADD);
        if (unlikely(error)) goto err;
        dst_ns = (namespace_t *)data.object;
        dst_ns_rights = data.rights;
    }

    handle_data_t src_obj;
    error = namespace_resolve(&src_obj, src_ns, src_obj_hnd);
    if (unlikely(error)) goto err2;

    switch (flags_mode) {
    case HYDROGEN_SET_HANDLE_FLAGS: break;
    case HYDROGEN_ADD_HANDLE_FLAGS: flags |= src_obj.flags; break;
    case HYDROGEN_REMOVE_HANDLE_FLAGS: flags = src_obj.flags & ~flags; break;
    default: error = EINVAL; goto err3;
    }

    if (src_obj.object->type == OBJECT_NAMESPACE) {
        if (unlikely((flags & NS_ILL_FLAGS) != 0)) {
            error = EINVAL;
            goto err3;
        }

        if (unlikely(src_ns != dst_ns)) {
            error = EPERM;
            goto err3;
        }
    }

    hydrogen_ret_t ret = namespace_add(dst_ns, dst_ns_rights, dst_hnd, src_obj.object, src_obj.rights & rights, flags);
    obj_deref(src_obj.object);
    if (dst_ns_hnd != HYDROGEN_THIS_NAMESPACE) obj_deref(&dst_ns->base);
    if (src_ns_hnd != HYDROGEN_THIS_NAMESPACE) obj_deref(&src_ns->base);
    return ret;

err3:
    obj_deref(src_obj.object);
err2:
    if (dst_ns_hnd != HYDROGEN_THIS_NAMESPACE) obj_deref(&dst_ns->base);
err:
    if (src_ns_hnd != HYDROGEN_THIS_NAMESPACE) obj_deref(&src_ns->base);
    return ret_error(error);
}

int hydrogen_namespace_remove(int ns_hnd, int handle) {
    if (unlikely(handle < 0)) return EBADF;

    namespace_t *ns;
    int error = namespace_or_this(&ns, ns_hnd, HYDROGEN_NAMESPACE_REMOVE);
    if (unlikely(error)) return error;

    error = namespace_remove(ns, handle);
    if (ns_hnd != HYDROGEN_THIS_NAMESPACE) obj_deref(&ns->base);
    return error;
}

int hydrogen_namespace_resolve(int ns_hnd, int handle, uint32_t *rights, uint32_t *flags) {
    if (unlikely(handle < 0)) return EBADF;

    namespace_t *ns;
    int error = namespace_or_this(&ns, ns_hnd, HYDROGEN_NAMESPACE_RESOLVE);
    if (unlikely(error)) return error;

    handle_data_t data;
    error = namespace_resolve(&data, ns, handle);
    if (unlikely(error)) goto ret;

    *rights = data.rights;
    *flags = data.flags;

ret:
    if (ns_hnd != HYDROGEN_THIS_NAMESPACE) obj_deref(&ns->base);
    return error;
}
