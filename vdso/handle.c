#include "hydrogen/handle.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "syscall.h"

int hydrogen_namespace_create(hydrogen_handle_t *ns) {
    hydrogen_handle_t ret;
    int error;
    SYSCALL0(SYSCALL_NAMESPACE_CREATE);
    if (likely(!error)) *ns = ret;
    return error;
}

int hydrogen_handle_create(hydrogen_handle_t ns, hydrogen_handle_t object, uint64_t rights, hydrogen_handle_t *handle) {
    hydrogen_handle_t ret;
    int error;
    SYSCALL3(SYSCALL_HANDLE_CREATE, ns, object, rights);
    if (likely(!error)) *handle = ret;
    return error;
}

int hydrogen_handle_close(hydrogen_handle_t ns, hydrogen_handle_t handle) {
    UNUSED int ret;
    int error;
    SYSCALL2(SYSCALL_HANDLE_CLOSE, ns, handle);
    return error;
}
