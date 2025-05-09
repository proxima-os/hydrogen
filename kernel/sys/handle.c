#include "hydrogen/handle.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "util/handle.h"
#include "util/object.h"
#include <stdint.h>

#define NAMESPACE_RIGHTS \
    (HYDROGEN_NAMESPACE_RESOLVE | HYDROGEN_NAMESPACE_REMOVE | HYDROGEN_NAMESPACE_ADD | HYDROGEN_NAMESPACE_CLONE)

int hydrogen_namespace_create(uint32_t flags) {
    if (unlikely((flags & ~(HANDLE_FLAGS & ~NS_ILL_FLAGS)) != 0)) return -EINVAL;

    namespace_t *ns;
    int ret = -namespace_create(&ns);
    if (unlikely(ret)) return -ret;

    ret = hnd_alloc(&ns->base, NAMESPACE_RIGHTS, flags);
    obj_deref(&ns->base);
    return ret;
}

static int resolve_or_this(namespace_t **out, int handle, object_rights_t rights) {
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

int hydrogen_namespace_clone(int ns_hnd, uint32_t flags) {
    if (unlikely((flags & ~(HANDLE_FLAGS & ~NS_ILL_FLAGS)) != 0)) return -EINVAL;

    namespace_t *src;
    int ret = -resolve_or_this(&src, ns_hnd, HYDROGEN_NAMESPACE_CLONE);
    if (unlikely(ret)) return ret;

    namespace_t *ns;
    ret = -namespace_clone(&ns, src);
    if (unlikely(ret)) goto ret;

    ret = hnd_alloc(&ns->base, NAMESPACE_RIGHTS, flags);
    obj_deref(&ns->base);
ret:
    if (ns_hnd != HYDROGEN_THIS_NAMESPACE) obj_deref(&src->base);
    return ret;
}

int hydrogen_namespace_add(
        int src_ns_hnd,
        int src_obj_hnd,
        int dst_ns_hnd,
        int dst_hnd,
        uint32_t rights,
        uint32_t flags
) {
    if (unlikely(src_obj_hnd < 0)) return -EBADF;
    if (dst_ns_hnd < 0 && unlikely(dst_hnd != HYDROGEN_THIS_NAMESPACE)) return -EINVAL;
    if (dst_hnd < 0 && unlikely(dst_hnd != HYDROGEN_INVALID_HANDLE)) return -EINVAL;
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return -EINVAL;

    namespace_t *src_ns;
    int ret = -resolve_or_this(&src_ns, src_ns_hnd, HYDROGEN_NAMESPACE_RESOLVE);
    if (unlikely(ret)) return ret;

    namespace_t *dst_ns;
    object_rights_t dst_ns_rights;

    if (dst_ns_hnd == HYDROGEN_THIS_NAMESPACE) {
        dst_ns = current_thread->namespace;
        dst_ns_rights = NAMESPACE_RIGHTS;
    } else {
        handle_data_t data;
        ret = -hnd_resolve(&data, dst_ns_hnd, OBJECT_NAMESPACE, HYDROGEN_NAMESPACE_ADD);
        if (unlikely(ret)) goto ret;
        dst_ns = (namespace_t *)data.object;
        dst_ns_rights = data.rights;
    }

    handle_data_t src_obj;
    ret = -namespace_resolve(&src_obj, src_ns, src_obj_hnd);
    if (unlikely(ret)) goto ret2;

    if (src_obj.object->type == OBJECT_NAMESPACE) {
        if (unlikely((flags & NS_ILL_FLAGS) != 0)) {
            ret = -EINVAL;
            goto ret3;
        }

        if (unlikely(src_ns != dst_ns)) {
            ret = -EPERM;
            goto ret3;
        }
    }

    ret = namespace_add(dst_ns, dst_ns_rights, dst_hnd, src_obj.object, src_obj.rights & rights, flags);
ret3:
    obj_deref(src_obj.object);
ret2:
    if (dst_ns_hnd != HYDROGEN_THIS_NAMESPACE) obj_deref(&dst_ns->base);
ret:
    if (src_ns_hnd != HYDROGEN_THIS_NAMESPACE) obj_deref(&src_ns->base);
    return ret;
}

int hydrogen_namespace_remove(int ns_hnd, int handle) {
    if (unlikely(handle < 0)) return EBADF;

    namespace_t *ns;
    int ret = resolve_or_this(&ns, ns_hnd, HYDROGEN_NAMESPACE_REMOVE);
    if (unlikely(ret)) return ret;

    ret = namespace_remove(ns, handle);
    if (ns_hnd != HYDROGEN_THIS_NAMESPACE) obj_deref(&ns->base);
    return ret;
}

int hydrogen_namespace_resolve(int ns_hnd, int handle, uint32_t *rights, uint32_t *flags) {
    if (unlikely(handle < 0)) return EBADF;

    namespace_t *ns;
    int ret = resolve_or_this(&ns, ns_hnd, HYDROGEN_NAMESPACE_RESOLVE);
    if (unlikely(ret)) return ret;

    handle_data_t data;
    ret = namespace_resolve(&data, ns, handle);
    if (unlikely(ret)) goto ret;

    *rights = data.rights;
    *flags = data.flags;

ret:
    if (ns_hnd != HYDROGEN_THIS_NAMESPACE) obj_deref(&ns->base);
    return ret;
}
