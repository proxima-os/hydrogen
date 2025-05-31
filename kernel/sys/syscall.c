#include "sys/syscall.h"
#include "arch/context.h"
#include "arch/pmap.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "kernel/filesystem.h"
#include "kernel/return.h"
#include "kernel/syscall.h"
#include "kernel/thread.h"
#include "kernel/types.h"
#include "sys/vdso.h"
#include "util/printk.h"
#include <hydrogen/eventqueue.h>
#include <hydrogen/filesystem.h>
#include <hydrogen/handle.h>
#include <hydrogen/hydrogen.h>
#include <hydrogen/interrupt.h>
#include <hydrogen/memory.h>
#include <hydrogen/process.h>
#include <hydrogen/signal.h>
#include <hydrogen/thread.h>
#include <hydrogen/time.h>
#include <hydrogen/types.h>
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
        printk("syscall: attempted to invoke syscall from outside vDSO (pc: %Z), sending SIGSYS\n", pc);
        __siginfo_t sig = {.__signo = __SIGSYS};
        queue_signal(
            current_thread->process,
            &current_thread->sig_target,
            &sig,
            QUEUE_SIGNAL_FORCE,
            &current_thread->fault_sig
        );
        return false;
    }

    return true;
}

static hydrogen_ret_t dispatch(ssize_t id, size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5) {
    switch (id) {
    case SYSCALL_THREAD_EXIT: hydrogen_thread_exit(a0);
    case SYSCALL_GET_NANOSECONDS_SINCE_BOOT: return ret_integer(hydrogen_boot_time());
    case SYSCALL_THREAD_YIELD: hydrogen_thread_yield(); return ret_error(0);
    case SYSCALL_NAMESPACE_CREATE: return hydrogen_namespace_create(a0);
    case SYSCALL_NAMESPACE_CLONE: return hydrogen_namespace_clone(a0, a1);
    case SYSCALL_NAMESPACE_ADD: return hydrogen_namespace_add(a0, a1, a2, a3, a4, a5);
    case SYSCALL_NAMESPACE_REMOVE: return ret_error(hydrogen_namespace_remove(a0, a1));
    case SYSCALL_NAMESPACE_RESOLVE: {
        uint32_t rights, flags;
        int error = hydrogen_namespace_resolve(a0, a1, &rights, &flags);
        return RET_MAYBE(integer, error, ((uint64_t)flags << 32) | rights);
    }
    case SYSCALL_VMM_CREATE: return hydrogen_vmm_create(a0);
    case SYSCALL_VMM_CLONE: return hydrogen_vmm_clone(a0, a1);
    case SYSCALL_VMM_MAP: return hydrogen_vmm_map(a0, a1, a2, a3, a4, a5);
    case SYSCALL_VMM_REMAP: return ret_error(hydrogen_vmm_remap(a0, a1, a2, a3));
    case SYSCALL_VMM_MOVE: return hydrogen_vmm_map(a0, a1, a2, a3, a4, a5);
    case SYSCALL_VMM_UNMAP: return ret_error(hydrogen_vmm_unmap(a0, a1, a2));
    case SYSCALL_VMM_READ: return ret_error(hydrogen_vmm_read(a0, (void *)a1, a2, a3));
    case SYSCALL_VMM_WRITE: return ret_error(hydrogen_vmm_write(a0, (const void *)a1, a2, a3));
    case SYSCALL_SET_REAL_TIME: return ret_error(hydrogen_set_real_time(a0 | ((__uint128_t)a1 << 64)));
    case SYSCALL_MEMORY_WAIT: return ret_error(hydrogen_memory_wait((uint32_t *)a0, a1, a2));
    case SYSCALL_MEMORY_WAKE: return hydrogen_memory_wake((uint32_t *)a0, a1);
    case SYSCALL_PROCESS_FIND: return hydrogen_process_find(a0, a1);
    case SYSCALL_PROCESS_CREATE: return hydrogen_process_create(a0);
    case SYSCALL_PROCESS_GETPID: return hydrogen_process_getpid(a0);
    case SYSCALL_PROCESS_GETPPID: return hydrogen_process_getppid(a0);
    case SYSCALL_PROCESS_GETPGID: return hydrogen_process_getpgid(a0);
    case SYSCALL_PROCESS_GETSID: return hydrogen_process_getsid(a0);
    case SYSCALL_PROCESS_SETPGID: return ret_error(hydrogen_process_setpgid(a0, a1));
    case SYSCALL_PROCESS_SETSID: return hydrogen_process_setsid(a0);
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
    case SYSCALL_THREAD_CREATE: return hydrogen_thread_create(a0, a1, a2, a3, a4, a5);
    case SYSCALL_THREAD_CLONE: return hydrogen_thread_clone(a0, a1, a2, a3);
    case SYSCALL_THREAD_REINIT: return ret_error(hydrogen_thread_reinit(a0, a1, a2, a3));
    case SYSCALL_MEM_OBJECT_CREATE: return hydrogen_mem_object_create(a0, a1);
    case SYSCALL_MEM_OBJECT_READ: return ret_error(hydrogen_mem_object_read(a0, (void *)a1, a2, a3));
    case SYSCALL_MEM_OBJECT_WRITE: return ret_error(hydrogen_mem_object_write(a0, (const void *)a1, a2, a3));
    case SYSCALL_THREAD_SLEEP: return ret_error(hydrogen_thread_sleep(a0));
    case SYSCALL_PROCESS_SIGACTION: return ret_error(hydrogen_process_sigaction(a0, a1, (const void *)a2, (void *)a3));
    case SYSCALL_THREAD_SIGMASK: return ret_error(hydrogen_thread_sigmask(a0, (const void *)a1, (void *)a2));
    case SYSCALL_THREAD_SIGALTSTACK: return ret_error(hydrogen_thread_sigaltstack((const void *)a0, (void *)a1));
    case SYSCALL_THREAD_SIGPENDING: return ret_integer(hydrogen_thread_sigpending());
    case SYSCALL_THREAD_SIGSUSPEND: return ret_error(hydrogen_thread_sigsuspend(a0));
    case SYSCALL_PROCESS_SEND_SIGNAL: return ret_error(hydrogen_process_send_signal(a0, a1));
    case SYSCALL_PROCESS_GROUP_SEND_SIGNAL: return ret_error(hydrogen_process_group_send_signal(a0, a1));
    case SYSCALL_THREAD_SEND_SIGNAL: return ret_error(hydrogen_thread_send_signal(a0, a1));
    case SYSCALL_THREAD_GET_ID: return hydrogen_thread_get_id(a0);
    case SYSCALL_THREAD_FIND: return hydrogen_thread_find(a0, a1, a2);
    case SYSCALL_PROCESS_SIGWAIT: return ret_error(hydrogen_process_sigwait(a0, a1, (void *)a2, a3));
    case SYSCALL_EVENT_QUEUE_CREATE: return hydrogen_event_queue_create(a0);
    case SYSCALL_EVENT_QUEUE_ADD: return ret_error(hydrogen_event_queue_add(a0, a1, a2, a3, (void *)a4, a5));
    case SYSCALL_EVENT_QUEUE_REMOVE: return hydrogen_event_queue_remove(a0, a1, a2, a3);
    case SYSCALL_EVENT_QUEUE_WAIT: return hydrogen_event_queue_wait(a0, (void *)a1, a2, a3);
    case SYSCALL_PROCESS_EXIT: hydrogen_process_exit(a0);
    case SYSCALL_PROCESS_WAIT: return ret_error(hydrogen_process_wait(a0, a1, (__siginfo_t *)a2, a3));
    case SYSCALL_PROCESS_WAIT_ID: return hydrogen_process_wait_id(a0, a1, (__siginfo_t *)a2, a3);
    case SYSCALL_MEM_OBJECT_RESIZE: return ret_error(hydrogen_mem_object_resize(a0, a1));
    case SYSCALL_PROCESS_GET_CPU_TIME:
        return ret_error(hydrogen_process_get_cpu_time((hydrogen_process_cpu_time_t *)a0));
    case SYSCALL_GET_HOST_NAME: return hydrogen_get_host_name((void *)a0, a1);
    case SYSCALL_SET_HOST_NAME: return ret_error(hydrogen_set_host_name((const void *)a0, a1));
    case SYSCALL_PROCESS_ALARM: return hydrogen_process_alarm(a0, a1);
    case SYSCALL_FS_CHDIR: return ret_error(hydrogen_fs_chdir(a0, a1, (const void *)a2, a3));
    case SYSCALL_FS_CHROOT: return ret_error(hydrogen_fs_chroot(a0, a1, (const void *)a2, a3));
    case SYSCALL_FS_UMASK: return hydrogen_fs_umask(a0, a1);
    case SYSCALL_FS_CREATE: return ret_error(hydrogen_fs_create(a0, (const void *)a1, a2, a3, a4));
    case SYSCALL_FS_SYMLINK: return ret_error(hydrogen_fs_symlink(a0, (const void *)a1, a2, (const void *)a3, a4));
    case SYSCALL_FS_LINK: {
        const link_syscall_args_t *ptr = (const void *)a0;
        link_syscall_args_t args;
        int error = verify_user_buffer(ptr, sizeof(*ptr));
        if (unlikely(error)) return ret_error(error);

        error = user_memcpy(&args, ptr, sizeof(*ptr));
        if (unlikely(error)) return ret_error(error);

        return ret_error(
            hydrogen_fs_link(args.rel, args.path, args.length, args.trel, args.target, args.tlength, args.flags)
        );
    }
    case SYSCALL_FS_UNLINK: return ret_error(hydrogen_fs_unlink(a0, (const void *)a1, a2, a3));
    case SYSCALL_FS_RENAME: return ret_error(hydrogen_fs_rename(a0, (const void *)a1, a2, a3, (const void *)a4, a5));
    case SYSCALL_FS_ACCESS: return ret_error(hydrogen_fs_access(a0, (const void *)a1, a2, a3, a4));
    case SYSCALL_FS_STAT:
        return ret_error(hydrogen_fs_stat(a0, (const void *)a1, a2, (hydrogen_file_information_t *)a3, a4));
    case SYSCALL_FS_READLINK: return hydrogen_fs_readlink(a0, (const void *)a1, a2, (void *)a3, a4);
    case SYSCALL_FS_CHMOD: return ret_error(hydrogen_fs_chmod(a0, (const void *)a1, a2, a3, a4));
    case SYSCALL_FS_CHOWN: return ret_error(hydrogen_fs_chown(a0, (const void *)a1, a2, a3, a4, a5));
    case SYSCALL_FS_UTIME: {
        const utime_syscall_args_t *ptr = (const void *)a3;
        utime_syscall_args_t args;
        int error = verify_user_buffer(ptr, sizeof(*ptr));
        if (unlikely(error)) return ret_error(error);

        error = user_memcpy(&args, ptr, sizeof(*ptr));
        if (unlikely(error)) return ret_error(error);

        return ret_error(hydrogen_fs_utime(a0, (const void *)a1, a2, args.atime, args.ctime, args.mtime, a4));
    }
    case SYSCALL_FS_TRUNCATE: return ret_error(hydrogen_fs_truncate(a0, (const void *)a1, a2, a3));
    case SYSCALL_FS_OPEN: return hydrogen_fs_open(a0, (const void *)a1, a2, a3, a4);
    case SYSCALL_FS_MMAP: return hydrogen_fs_mmap(a0, a1, a2, a3, a4, a5);
    case SYSCALL_FS_PREAD: return hydrogen_fs_pread(a0, (void *)a1, a2, a3);
    case SYSCALL_FS_PWRITE: return hydrogen_fs_pwrite(a0, (const void *)a1, a2, a3);
    case SYSCALL_FS_SEEK: return hydrogen_fs_seek(a0, a1, a2);
    case SYSCALL_FS_READ: return hydrogen_fs_read(a0, (void *)a1, a2);
    case SYSCALL_FS_READDIR: return hydrogen_fs_readdir(a0, (void *)a1, a2);
    case SYSCALL_FS_WRITE: return hydrogen_fs_write(a0, (const void *)a1, a2);
    case SYSCALL_FS_FFLAGS: return hydrogen_fs_fflags(a0, a1);
    case SYSCALL_FS_FPATH: return hydrogen_fs_fpath(a0, (void *)a1, a2);
    case SYSCALL_THREAD_EXEC: {
        const exec_syscall_args_t *ptr = (const void *)a3;
        exec_syscall_args_t args;
        int error = verify_user_buffer(ptr, sizeof(*ptr));
        if (unlikely(error)) return ret_error(error);

        error = user_memcpy(&args, ptr, sizeof(*ptr));
        if (unlikely(error)) return ret_error(error);

        return hydrogen_thread_exec(a0, a1, a2, args.argc, args.argv, args.envc, args.envp, a4);
    }
    case SYSCALL_FS_FSTAT: return ret_error(hydrogen_fs_fstat(a0, (hydrogen_file_information_t *)a1));
    case SYSCALL_FS_FCHMOD: return ret_error(hydrogen_fs_fchmod(a0, a1));
    case SYSCALL_FS_FCHOWN: return ret_error(hydrogen_fs_fchown(a0, a1, a2));
    case SYSCALL_FS_FUTIME: {
        const utime_syscall_args_t *ptr = (const void *)a1;
        utime_syscall_args_t args;
        int error = verify_user_buffer(ptr, sizeof(*ptr));
        if (unlikely(error)) return ret_error(error);

        error = user_memcpy(&args, ptr, sizeof(*ptr));
        if (unlikely(error)) return ret_error(error);

        return ret_error(hydrogen_fs_futime(a0, args.atime, args.ctime, args.mtime));
    }
    case SYSCALL_FS_FTRUNCATE: return ret_error(hydrogen_fs_ftruncate(a0, a1));
    case SYSCALL_FS_FOPEN: return hydrogen_fs_fopen(a0, a1);
    case SYSCALL_FS_PIPE: {
        int fds[2];
        int error = hydrogen_fs_pipe(fds, a0);
        if (unlikely(error)) return ret_error(error);
        return ret_integer(((uint64_t)fds[1] << 32) | fds[0]);
    }
    case SYSCALL_FS_IOCTL: return hydrogen_fs_ioctl(a0, a1, (void *)a2, a3);
    case SYSCALL_FS_FCHDIR: return ret_error(hydrogen_fs_fchdir(a0, a1));
    case SYSCALL_FS_FCHROOT: return ret_error(hydrogen_fs_fchroot(a0, a1));
    case SYSCALL_THREAD_GET_CPU_TIME: return ret_error(hydrogen_thread_get_cpu_time((hydrogen_cpu_time_t *)a0));
    case SYSCALL_INTERRUPT_WAIT: return ret_error(hydrogen_interrupt_wait(a0, a1, a2));
    case SYSCALL_INTERRUPT_COMPLETE: return ret_error(hydrogen_interrupt_complete(a0));
    case SYSCALL_THREAD_SET_CPU_AFFINITY: return ret_error(hydrogen_thread_set_cpu_affinity((const uint64_t *)a0, a1));
    case SYSCALL_THREAD_GET_CPU_AFFINITY: return ret_error(hydrogen_thread_get_cpu_affinity((uint64_t *)a0, a1));
    case SYSCALL_THREAD_SET_SCHEDULER: return ret_error(hydrogen_thread_set_scheduler(a0, a1));
    case SYSCALL_THREAD_GET_SCHEDULER: {
        int priority;
        int scheduler = hydrogen_thread_get_scheduler(&priority);
        return ret_integer(((uint64_t)priority << 32) | scheduler);
    }
    default: return ret_error(ENOSYS);
    }
}

void do_syscall(ssize_t id, size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5) {
    arch_context_set_syscall_return(current_thread->user_ctx, dispatch(id, a0, a1, a2, a3, a4, a5));
}

int verify_user_buffer(const void *ptr, size_t size) {
    if (unlikely(size == 0)) return 0;

    uintptr_t head = (uintptr_t)ptr;
    uintptr_t tail = head + (size - 1);
    if (unlikely(tail < head)) return EFAULT;
    if (unlikely(tail > arch_pt_max_user_addr())) return EFAULT;

    return 0;
}
