#include "hydrogen/handle.h"
#include "arch/syscall.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "vdso.h"
#include <stdint.h>

EXPORT hydrogen_ret_t hydrogen_namespace_create(uint32_t flags) {
    return SYSCALL1(SYSCALL_NAMESPACE_CREATE, flags);
}

EXPORT hydrogen_ret_t hydrogen_namespace_clone(int ns, uint32_t flags) {
    return SYSCALL2(SYSCALL_NAMESPACE_CLONE, ns, flags);
}

EXPORT hydrogen_ret_t hydrogen_namespace_add(int src_ns, int src_obj, int dst_ns, int dst_hnd, uint32_t rights, uint32_t flags) {
    return SYSCALL6(SYSCALL_NAMESPACE_ADD, src_ns, src_obj, dst_ns, dst_hnd, rights, flags);
}

EXPORT int hydrogen_namespace_remove(int ns, int handle) {
    return SYSCALL2(SYSCALL_NAMESPACE_REMOVE, ns, handle).error;
}

EXPORT int hydrogen_namespace_resolve(int ns, int handle, uint32_t *rights, uint32_t *flags) {
    hydrogen_ret_t ret = SYSCALL2(SYSCALL_NAMESPACE_RESOLVE, ns, handle);
    if (unlikely(ret.error)) return ret.error;

    if (rights) *rights = ret.integer & 0xffffffff;
    if (flags) *flags = ret.integer >> 32;

    return 0;
}
