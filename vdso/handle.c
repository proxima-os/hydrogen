#include "hydrogen/handle.h"
#include "hydrogen/types.h"
#include "kernel/syscall.h"
#include "syscall.h"
#include "vdso.h"

EXPORT hydrogen_ret_t hydrogen_namespace_create(void) {
    return SYSCALL0(SYSCALL_NAMESPACE_CREATE);
}

EXPORT hydrogen_ret_t hydrogen_namespace_clone(hydrogen_handle_t namespace) {
    return SYSCALL1(SYSCALL_NAMESPACE_CLONE, namespace);
}

EXPORT hydrogen_ret_t hydrogen_handle_create(hydrogen_handle_t ns, hydrogen_handle_t object, uint64_t rights) {
    return SYSCALL3(SYSCALL_HANDLE_CREATE, ns, object, rights);
}

EXPORT int hydrogen_handle_close(hydrogen_handle_t ns, hydrogen_handle_t handle) {
    return SYSCALL2(SYSCALL_HANDLE_CLOSE, ns, handle).error;
}
