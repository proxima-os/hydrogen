#include "sys/syscall.h"
#include "arch/context.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "hydrogen/handle.h"
#include "hydrogen/thread.h"
#include "hydrogen/time.h"
#include "hydrogen/types.h"
#include "kernel/return.h"
#include "kernel/syscall.h"
#include "kernel/types.h"
#include <stddef.h>
#include <stdint.h>

static hydrogen_ret_t dispatch(ssize_t id, size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5) {
    switch (id) {
    case SYSCALL_THREAD_EXIT: hydrogen_thread_exit(a0);
    case SYSCALL_GET_NANOSECONDS_SINCE_BOOT: return ret_integer(hydrogen_boot_time());
    case SYSCALL_THREAD_YIELD: hydrogen_thread_yield(); return ret_error(0);
    case SYSCALL_NAMESPACE_CREATE: return ret_error(hydrogen_namespace_create(a0));
    case SYSCALL_NAMESPACE_CLONE: return ret_error(hydrogen_namespace_clone(a0, a1));
    case SYSCALL_NAMESPACE_ADD: return ret_error(hydrogen_namespace_add(a0, a1, a2, a3, a4, a5));
    case SYSCALL_NAMESPACE_REMOVE: return ret_error(hydrogen_namespace_remove(a0, a1));
    case SYSCALL_NAMESPACE_RESOLVE: {
        uint32_t rights, flags;
        int error = hydrogen_namespace_resolve(a0, a1, &rights, &flags);
        return RET_MAYBE(integer, error, (flags << 16) | rights);
    }
    default: return ret_error(ENOSYS);
    }
}

void do_syscall(ssize_t id, size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5) {
    arch_context_set_syscall_return(current_thread->user_ctx, dispatch(id, a0, a1, a2, a3, a4, a5));
}
