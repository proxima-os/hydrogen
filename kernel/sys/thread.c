#include "sys/thread.h"
#include "arch/context.h"
#include "arch/pmap.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "fs/vfs.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/mutex.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "sys/exec.h"
#include "sys/handle.h"
#include "sys/memory.h"
#include "sys/process.h"
#include "sys/syscall.h"
#include "sys/transition.h"
#include "util/handle.h"
#include "util/object.h"
#include <hydrogen/handle.h>
#include <hydrogen/memory.h>
#include <hydrogen/process.h>
#include <hydrogen/signal.h>
#include <hydrogen/thread.h>
#include <hydrogen/types.h>
#include <stdint.h>

#define THREAD_RIGHTS THIS_THREAD_RIGHTS

static int verify_pc_sp(uintptr_t pc, uintptr_t sp) {
    if (unlikely(pc > arch_pt_max_user_addr())) return EINVAL;
    if (unlikely(sp > arch_pt_max_user_addr())) return EINVAL;
    return 0;
}

static int vmm_for_create(vmm_t **out, int handle) {
    if (handle == HYDROGEN_CLONED_VMM) {
        return vmm_clone(out, current_thread->vmm);
    }

    return vmm_or_this(out, handle, THIS_VMM_RIGHTS);
}

// Adds the thread to the process, wakes it, and returns a handle to it.
static hydrogen_ret_t finalize_thread(process_t *process, thread_t *thread, uint32_t flags) {
    namespace_t *ns = current_thread->namespace;

    int error = hnd_reserve(ns);
    if (unlikely(error)) return ret_error(error);

    handle_data_t *data = vmalloc(sizeof(*data));
    if (unlikely(!data)) return ret_error(ENOMEM);

    error = proc_thread_create(process, thread);

    if (unlikely(error)) {
        mutex_rel(&ns->update_lock);
        vfree(data, sizeof(*data));
        hnd_unreserve(ns);
        return ret_error(error);
    }

    thread->process = process;
    obj_ref(&process->base);
    int handle = hnd_alloc_reserved(ns, &thread->base, THREAD_RIGHTS, flags, data);
    sched_wake(thread);
    return ret_integer(handle);
}

struct launch_ctx {
    uintptr_t pc;
    uintptr_t sp;
};

static void launch_user_thread(void *ptr) {
    struct launch_ctx *ctx = ptr;
    uintptr_t pc = ctx->pc;
    uintptr_t sp = ctx->sp;
    vfree(ctx, sizeof(*ctx));
    arch_enter_user_mode(pc, sp);
}

hydrogen_ret_t hydrogen_thread_create(
    int process,
    int vmm_hnd,
    int namespace,
    uintptr_t pc,
    uintptr_t sp,
    uint32_t flags
) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return ret_error(EINVAL);

    int error = verify_pc_sp(pc, sp);
    if (unlikely(error)) return ret_error(error);

    process_t *proc;
    error = process_or_this(&proc, process, THIS_PROCESS_RIGHTS);
    if (unlikely(error)) return ret_error(error);

    namespace_t *ns;
    error = namespace_or_this(&ns, namespace, THIS_NAMESPACE_RIGHTS);
    if (unlikely(error)) goto err;

    vmm_t *vmm;
    error = vmm_for_create(&vmm, vmm_hnd);
    if (unlikely(error)) goto err2;

    struct launch_ctx *ctx = vmalloc(sizeof(*ctx));
    if (unlikely(!ctx)) {
        error = ENOMEM;
        goto err3;
    }

    ctx->pc = pc;
    ctx->sp = sp;

    thread_t *thread;
    error = sched_create_thread(&thread, launch_user_thread, ctx, NULL, NULL, THREAD_USER);
    if (unlikely(error)) goto err4;

    thread->vmm = vmm;
    thread->namespace = ns;
    obj_ref(&vmm->base);
    obj_ref(&ns->base);

    hydrogen_ret_t ret = finalize_thread(proc, thread, flags);
    obj_deref(&thread->base);
    if (unlikely(ret.error)) vfree(ctx, sizeof(*ctx));
    if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&vmm->base);
    if (namespace != HYDROGEN_THIS_NAMESPACE) obj_deref(&ns->base);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret;

err4:
    vfree(ctx, sizeof(*ctx));
err3:
    if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&vmm->base);
err2:
    if (namespace != HYDROGEN_THIS_NAMESPACE) obj_deref(&ns->base);
err:
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret_error(error);
}

static _Noreturn void do_exec(void *ctx) {
    exec_data_t *data = ctx;
    exec_finalize(data);
    uintptr_t pc = data->pc;
    uintptr_t sp = data->sp;
    vfree(data, sizeof(*data));
    arch_enter_user_mode(pc, sp);
}

hydrogen_ret_t hydrogen_thread_exec(
    int process,
    int namespace,
    int image,
    size_t argc,
    const hydrogen_string_t *argv,
    size_t envc,
    const hydrogen_string_t *envp,
    uint32_t flags
) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return ret_error(EINVAL);

    int error = verify_user_buffer(argv, argc * sizeof(*argv));
    if (unlikely(error)) return ret_error(error);

    error = verify_user_buffer(envp, envc * sizeof(*envp));
    if (unlikely(error)) return ret_error(error);

    process_t *proc;
    error = process_or_this(&proc, process, THIS_PROCESS_RIGHTS);
    if (unlikely(error)) return ret_error(error);

    namespace_t *ns;
    error = namespace_or_this(&ns, namespace, THIS_NAMESPACE_RIGHTS);
    if (unlikely(error)) goto err;

    handle_data_t data;
    error = hnd_resolve(&data, image, OBJECT_FILE_DESCRIPTION, 0);
    if (unlikely(error)) goto err2;
    file_t *file = (file_t *)data.object;

    exec_data_t *exec_data = vmalloc(sizeof(*exec_data));
    if (unlikely(!exec_data)) {
        error = ENOMEM;
        goto err3;
    }

    ident_t *ident = ident_get(current_thread->process);
    error = create_exec_data(exec_data, proc, file, ident, argc, argv, envc, envp, true);
    ident_deref(ident);
    if (unlikely(error)) goto err4;

    if (proc == current_thread->process) {
        obj_deref(&file->base);

        mutex_acq(&proc->threads_lock, 0, false);
        __atomic_store_n(&proc->exiting, true, __ATOMIC_RELEASE);

        LIST_FOREACH(proc->threads, thread_t, process_node, thread) {
            if (thread != current_thread) {
                sched_interrupt(thread, true);
            }
        }

        proc_wait_until_single_threaded();
        __atomic_store_n(&proc->exiting, false, __ATOMIC_RELEASE);
        mutex_rel(&proc->threads_lock);

        if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
        if (namespace != HYDROGEN_THIS_NAMESPACE) obj_deref(&current_thread->namespace->base);
        obj_deref(&current_thread->vmm->base);

        current_thread->namespace = ns;
        current_thread->vmm = exec_data->vmm;

        do_exec(exec_data);
    }

    thread_t *thread;
    error = sched_create_thread(&thread, do_exec, exec_data, NULL, NULL, THREAD_USER);
    if (unlikely(error)) goto err5;

    thread->vmm = exec_data->vmm;
    thread->namespace = ns;
    exec_data->vmm = NULL;
    obj_ref(&ns->base);

    hydrogen_ret_t ret = finalize_thread(proc, thread, flags);
    obj_deref(&thread->base);
    if (unlikely(ret.error)) {
        error = ret.error;
        goto err5;
    }

    obj_deref(&file->base);

    if (namespace != HYDROGEN_THIS_NAMESPACE) obj_deref(&ns->base);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);

    return ret;
err5:
    free_exec_data(exec_data);
err4:
    vfree(exec_data, sizeof(*exec_data));
err3:
    obj_deref(&file->base);
err2:
    if (namespace != HYDROGEN_THIS_NAMESPACE) obj_deref(&ns->base);
err:
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret_error(error);
}

static void clone_user_thread(void *ptr) {
    arch_context_t *ctx = ptr;
    arch_context_t context = *ctx;
    vfree(ctx, sizeof(*ctx));
    arch_context_set_syscall_return(&context, ret_integer(HYDROGEN_INVALID_HANDLE));
    arch_enter_user_mode_context(&context);
}

hydrogen_ret_t hydrogen_thread_clone(int process, int vmm_hnd, int namespace, uint32_t flags) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return ret_error(EINVAL);

    process_t *proc;
    int error = process_or_this(&proc, process, THIS_PROCESS_RIGHTS);
    if (unlikely(error)) return ret_error(error);

    namespace_t *ns;
    error = namespace_or_this(&ns, namespace, THIS_NAMESPACE_RIGHTS);
    if (unlikely(error)) goto err;

    vmm_t *vmm;
    error = vmm_for_create(&vmm, vmm_hnd);
    if (unlikely(error)) goto err2;

    arch_context_t *ctx = vmalloc(sizeof(*ctx));
    if (unlikely(!ctx)) {
        error = ENOMEM;
        goto err3;
    }
    memcpy(ctx, current_thread->user_ctx, sizeof(*ctx));

    thread_t *thread;
    error = sched_create_thread(&thread, clone_user_thread, ctx, NULL, NULL, THREAD_USER);
    if (unlikely(error)) goto err4;

    thread->vmm = vmm;
    thread->namespace = ns;
    obj_ref(&vmm->base);
    obj_ref(&ns->base);

    thread->sig_stack = current_thread->sig_stack;

    hydrogen_ret_t ret = finalize_thread(proc, thread, flags);
    obj_deref(&thread->base);
    if (unlikely(error < 0)) vfree(ctx, sizeof(*ctx));
    if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&vmm->base);
    if (namespace != HYDROGEN_THIS_NAMESPACE) obj_deref(&ns->base);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret;

err4:
    vfree(ctx, sizeof(*ctx));
err3:
    if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&vmm->base);
err2:
    if (namespace != HYDROGEN_THIS_NAMESPACE) obj_deref(&ns->base);
err:
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret_error(error);
}

int hydrogen_thread_reinit(int vmm_hnd, int namespace, uintptr_t pc, uintptr_t sp) {
    int error = verify_pc_sp(pc, sp);
    if (unlikely(error)) return error;

    namespace_t *ns;
    error = namespace_or_this(&ns, namespace, THIS_NAMESPACE_RIGHTS);
    if (unlikely(error)) return error;

    vmm_t *vmm;
    error = vmm_for_create(&vmm, vmm_hnd);
    if (unlikely(error)) {
        if (namespace != HYDROGEN_THIS_NAMESPACE) obj_deref(&ns->base);
        return error;
    }

    if (vmm != current_thread->vmm) {
        obj_deref(&vmm_switch(vmm)->base);
    } else if (vmm_hnd != HYDROGEN_THIS_VMM) {
        obj_deref(&vmm->base);
    }

    if (ns != current_thread->namespace) {
        obj_deref(&current_thread->namespace->base);
        current_thread->namespace = ns;
    } else if (namespace != HYDROGEN_THIS_NAMESPACE) {
        obj_deref(&ns->base);
    }

    arch_enter_user_mode(pc, sp);
}

void hydrogen_thread_yield(void) {
    sched_yield();
}

_Noreturn void hydrogen_thread_exit(int status) {
    sched_exit(status);
}

int hydrogen_thread_sleep(uint64_t deadline) {
    sched_prepare_wait(true);
    int error = sched_perform_wait(deadline);
    if (likely(error == ETIMEDOUT)) error = 0;
    return error;
}

int hydrogen_thread_sigmask(int how, const __sigset_t *set, __sigset_t *oset) {
    if (oset) {
        int error = verify_user_buffer(oset, sizeof(*oset));
        if (unlikely(error)) return error;

        error = user_memcpy(oset, &current_thread->sig_mask, sizeof(*oset));
        if (unlikely(error)) return error;
    }

    if (set) {
        int error = verify_user_buffer(set, sizeof(*set));
        if (unlikely(error)) return error;

        __sigset_t param;
        error = user_memcpy(&param, set, sizeof(*set));
        if (unlikely(error)) return error;

        switch (how) {
        case __SIG_BLOCK: current_thread->sig_mask |= param; break;
        case __SIG_SETMASK: current_thread->sig_mask = param; break;
        case __SIG_UNBLOCK: current_thread->sig_mask &= ~param; break;
        default: return EINVAL;
        }
    }

    return 0;
}

int hydrogen_thread_sigaltstack(const __stack_t *ss, __stack_t *oss) {
    if (oss) {
        int error = verify_user_buffer(oss, sizeof(*oss));
        if (unlikely(error)) return error;

        error = user_memcpy(oss, &current_thread->sig_stack, sizeof(*oss));
        if (unlikely(error)) return error;
    }

    if (ss) {
        if (unlikely(current_thread->sig_stack.__flags & __SS_ONSTACK)) return EPERM;

        int error = verify_user_buffer(ss, sizeof(*ss));
        if (unlikely(error)) return error;

        __stack_t stack;
        error = user_memcpy(&stack, ss, sizeof(*ss));
        if (unlikely(error)) return error;

        if (unlikely((stack.__flags & ~__SS_DISABLE) != 0)) return EINVAL;

        if ((stack.__flags & __SS_DISABLE) == 0) {
            if (unlikely(stack.__size < __MINSIGSTKSZ)) return ENOMEM;

            error = verify_user_buffer(stack.__pointer, stack.__size);
            if (unlikely(error)) return error;
        }

        current_thread->sig_stack = stack;
    }

    return 0;
}

__sigset_t hydrogen_thread_sigpending(void) {
    __sigset_t set = 0;
    set |= __atomic_load_n(&current_thread->sig_target.queue_map, __ATOMIC_ACQUIRE);
    set |= __atomic_load_n(&current_thread->process->sig_target.queue_map, __ATOMIC_ACQUIRE);
    set &= current_thread->sig_mask;
    return set;
}

int hydrogen_thread_sigsuspend(__sigset_t mask) {
    arch_context_set_syscall_return(current_thread->user_ctx, ret_error(EINTR));

    for (;;) {
        sched_prepare_wait(true);

        if (!check_signals(&current_thread->sig_target, false, mask) &&
            !check_signals(&current_thread->process->sig_target, false, mask)) {
            sched_perform_wait(0);
        } else {
            sched_cancel_wait();
            break;
        }

        if (__atomic_load_n(&current_thread->process->exiting, __ATOMIC_ACQUIRE)) {
            sched_exit(0);
        }
    }

    arch_enter_user_mode_context(current_thread->user_ctx);
}

int hydrogen_thread_send_signal(int thread_hnd, int signal) {
    if (unlikely(signal < 0) || unlikely(signal >= __NSIG)) return EINVAL;

    thread_t *thread;
    int error = thread_or_this(&thread, thread_hnd, 0);
    if (unlikely(error)) return error;

    __siginfo_t info;
    create_user_siginfo(&info, signal);
    info.__code = __SI_TKILL;

    if (unlikely(!can_send_signal(thread->process, &info))) {
        error = EPERM;
        goto ret;
    }

    if (signal == 0) goto ret;

    error = queue_signal(thread->process, &thread->sig_target, &info, 0, NULL);
ret:
    if (thread_hnd != HYDROGEN_THIS_THREAD) obj_deref(&thread->base);
    return error;
}

hydrogen_ret_t hydrogen_thread_get_id(int thread_hnd) {
    thread_t *thread;
    int error = thread_or_this(&thread, thread_hnd, 0);
    if (unlikely(error)) return ret_error(error);

    int id = thread->pid->id;
    if (thread_hnd != HYDROGEN_THIS_THREAD) obj_deref(&thread->base);
    return ret_integer(id);
}

hydrogen_ret_t hydrogen_thread_find(int process, int thread_id, uint32_t flags) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return ret_error(EINVAL);
    if (unlikely(thread_id == 0)) return ret_error(ESRCH);

    if (thread_id < 0 || thread_id == current_thread->pid->id) {
        return hnd_alloc(&current_thread->base, THIS_THREAD_RIGHTS, flags);
    }

    thread_t *thread;
    int error = resolve_thread(&thread, thread_id);
    if (unlikely(error)) return ret_error(error);

    if (process != HYDROGEN_INVALID_HANDLE) {
        process_t *proc;
        error = process_or_this(&proc, process, 0);
        if (unlikely(error)) goto err;

        bool ok = proc == thread->process;
        if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
        if (!ok) {
            error = ESRCH;
            goto err;
        }
    }

    hydrogen_ret_t ret = hnd_alloc(&thread->base, 0, flags);
    obj_deref(&thread->base);
    return ret;

err:
    obj_deref(&thread->base);
    return ret_error(error);
}

int hydrogen_thread_get_cpu_time(hydrogen_cpu_time_t *time) {
    int error = verify_user_buffer(time, sizeof(*time));
    if (unlikely(error)) return error;

    sched_commit_time_accounting();

    preempt_state_t state = preempt_lock();
    hydrogen_cpu_time_t data = {.user = current_thread->user_time, .kernel = current_thread->kern_time};
    preempt_unlock(state);

    return user_memcpy(time, &data, sizeof(*time));
}
