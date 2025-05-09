#include "sys/syscall.h"
#include "arch/context.h"
#include "arch/pmap.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "hydrogen/handle.h"
#include "hydrogen/memory.h"
#include "hydrogen/process.h"
#include "hydrogen/thread.h"
#include "hydrogen/time.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "kernel/syscall.h"
#include "kernel/types.h"
#include "sys/vdso.h"
#include "util/panic.h"
#include <stddef.h>
#include <stdint.h>

static bool is_in_vdso(uintptr_t pc) {
    // note: this doesn't protect against the scenario where a thread performs a syscall
    // from outside the vdso and another thread unmaps the code that did the syscall and
    // maps the vdso in its place before this check happens. that's fine; this check isn't
    // meant to provide security, it's just a way to discourage devs from doing syscalls
    // manually
    uintptr_t vdso_base = __atomic_load_n(&current_thread->vmm->vdso_addr, __ATOMIC_RELAXED);
    if (unlikely(vdso_base == 0)) return false;

    return vdso_base <= pc && pc < vdso_base + (vdso_size - vdso_image_offset);
}

bool prepare_syscall(uintptr_t pc) {
    if (unlikely(!is_in_vdso(pc))) {
        panic("Syscall from outside vDSO. TODO: Send a signal here instead of panicking");
        return false;
    }

    return true;
}

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
    case SYSCALL_VMM_CREATE: return ret_error(hydrogen_vmm_create(a0));
    case SYSCALL_VMM_CLONE: return ret_error(hydrogen_vmm_clone(a0, a1));
    case SYSCALL_VMM_MAP: return hydrogen_vmm_map(a0, a1, a2, a3, a4, a5);
    case SYSCALL_VMM_REMAP: return ret_error(hydrogen_vmm_remap(a0, a1, a2, a3));
    case SYSCALL_VMM_UNMAP: return ret_error(hydrogen_vmm_unmap(a0, a1, a2));
    case SYSCALL_VMM_READ: return ret_error(hydrogen_vmm_read(a0, (void *)a1, a2, a3));
    case SYSCALL_VMM_WRITE: return ret_error(hydrogen_vmm_write(a0, (const void *)a1, a2, a3));
    case SYSCALL_SET_REAL_TIME: return ret_error(hydrogen_set_real_time(a0));
    case SYSCALL_MEMORY_WAIT: return ret_error(hydrogen_memory_wait((uint32_t *)a0, a1, a2));
    case SYSCALL_MEMORY_WAKE: return hydrogen_memory_wake((uint32_t *)a0, a1);
    case SYSCALL_PROCESS_FIND: return ret_error(hydrogen_process_find(a0, a1));
    case SYSCALL_PROCESS_CREATE: return ret_error(hydrogen_process_create(a0));
    case SYSCALL_PROCESS_GETPID: return ret_error(hydrogen_process_getpid(a0));
    case SYSCALL_PROCESS_GETPPID: return ret_error(hydrogen_process_getppid(a0));
    case SYSCALL_PROCESS_GETPGID: return ret_error(hydrogen_process_getpgid(a0));
    case SYSCALL_PROCESS_GETSID: return ret_error(hydrogen_process_getsid(a0));
    case SYSCALL_PROCESS_SETPGID: return ret_error(hydrogen_process_setpgid(a0, a1));
    case SYSCALL_PROCESS_SETSID: return ret_error(hydrogen_process_setsid(a0));
    case SYSCALL_PROCESS_GETGID: return hydrogen_process_getgid(a0);
    case SYSCALL_PROCESS_GETUID: return hydrogen_process_getuid(a0);
    case SYSCALL_PROCESS_GETEGID: return hydrogen_process_getegid(a0);
    case SYSCALL_PROCESS_GETEUID: return hydrogen_process_geteuid(a0);
    case SYSCALL_PROCESS_GETRESGID: return ret_error(hydrogen_process_getresgid(a0, (uint32_t *)a1));
    case SYSCALL_PROCESS_GETRESUID: return ret_error(hydrogen_process_getresuid(a0, (uint32_t *)a1));
    case SYSCALL_PROCESS_GETGROUPS: return hydrogen_process_getgroups(a0, (uint32_t *)a1, a2);
    case SYSCALL_PROCESS_SETGID: return ret_error(hydrogen_process_setgid(a0, a1));
    case SYSCALL_PROCESS_SETUID: return ret_error(hydrogen_process_setuid(a0, a1));
    case SYSCALL_PROCESS_SETEGID: return ret_error(hydrogen_process_setegid(a0, a1));
    case SYSCALL_PROCESS_SETEUID: return ret_error(hydrogen_process_seteuid(a0, a1));
    case SYSCALL_PROCESS_SETREGID: return ret_error(hydrogen_process_setregid(a0, a1, a2));
    case SYSCALL_PROCESS_SETREUID: return ret_error(hydrogen_process_setreuid(a0, a1, a2));
    case SYSCALL_PROCESS_SETRESGID: return ret_error(hydrogen_process_setresgid(a0, a1, a2, a3));
    case SYSCALL_PROCESS_SETRESUID: return ret_error(hydrogen_process_setresuid(a0, a1, a2, a3));
    case SYSCALL_PROCESS_SETGROUPS: return ret_error(hydrogen_process_setgroups(a0, (const uint32_t *)a1, a2));
    default: return ret_error(ENOSYS);
    }
}

void do_syscall(ssize_t id, size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5) {
    arch_context_set_syscall_return(current_thread->user_ctx, dispatch(id, a0, a1, a2, a3, a4, a5));
}

int verify_user_buffer(uintptr_t start, size_t size) {
    if (unlikely(size == 0)) return 0;

    uintptr_t tail = start + (size - 1);
    if (unlikely(tail < start)) return EFAULT;
    if (unlikely(tail > arch_pt_max_user_addr())) return EFAULT;

    return 0;
}
