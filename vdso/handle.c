#include "hydrogen/handle.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "syscall.h"
#include "vdso.h"

EXPORT hydrogen_ret_t hydrogen_namespace_create(void) {
    hydrogen_handle_t ret;
    int error;
    SYSCALL0(SYSCALL_NAMESPACE_CREATE);
    return (hydrogen_ret_t){.error = error, .handle = ret};
}

EXPORT hydrogen_ret_t hydrogen_handle_create(hydrogen_handle_t ns, hydrogen_handle_t object, uint64_t rights) {
    hydrogen_handle_t ret;
    int error;
    SYSCALL3(SYSCALL_HANDLE_CREATE, ns, object, rights);
    return (hydrogen_ret_t){.error = error, .handle = ret};
}

EXPORT int hydrogen_handle_close(hydrogen_handle_t ns, hydrogen_handle_t handle) {
    UNUSED int ret;
    int error;
    SYSCALL2(SYSCALL_HANDLE_CLOSE, ns, handle);
    return error;
}
