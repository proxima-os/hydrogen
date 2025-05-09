#include "hydrogen/thread.h"
#include "arch/context.h"
#include "arch/pmap.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "hydrogen/handle.h"
#include "hydrogen/memory.h"
#include "hydrogen/process.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/mutex.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "sys/handle.h"
#include "sys/memory.h"
#include "sys/process.h"
#include "sys/thread.h"
#include "sys/transition.h"
#include "util/handle.h"
#include "util/object.h"
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
static int finalize_thread(process_t *process, thread_t *thread, uint32_t flags) {
    namespace_t *ns = current_thread->namespace;

    handle_data_t *data = vmalloc(sizeof(*data));
    if (unlikely(!data)) return ENOMEM;
    memset(data, 0, sizeof(*data));
    data->object = &thread->base;
    data->flags = flags;
    data->rights = THREAD_RIGHTS;

    mutex_acq(&ns->update_lock, 0, false);

    int handle = hnd_reserve(ns);

    if (unlikely(handle < 0)) {
        mutex_rel(&ns->update_lock);
        vfree(data, sizeof(*data));
        return handle;
    }

    int error = -proc_thread_create(process, thread);

    if (unlikely(error)) {
        mutex_rel(&ns->update_lock);
        vfree(data, sizeof(*data));
        return error;
    }

    thread->process = process;
    obj_ref(&process->base);
    hnd_assoc(ns, handle, data);
    mutex_rel(&ns->update_lock);
    sched_wake(thread);
    return handle;
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

int hydrogen_thread_create(int process, int vmm_hnd, int namespace, uintptr_t pc, uintptr_t sp, uint32_t flags) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return -EINVAL;

    int ret = -verify_pc_sp(pc, sp);
    if (unlikely(ret)) return ret;

    process_t *proc;
    ret = -process_or_this(&proc, process, THIS_PROCESS_RIGHTS);
    if (unlikely(ret)) return ret;

    namespace_t *ns;
    ret = -namespace_or_this(&ns, namespace, THIS_NAMESPACE_RIGHTS);
    if (unlikely(ret)) goto ret;

    vmm_t *vmm;
    ret = -vmm_for_create(&vmm, vmm_hnd);
    if (unlikely(ret)) goto ret2;

    struct launch_ctx *ctx = vmalloc(sizeof(*ctx));
    if (unlikely(!ctx)) {
        ret = -ENOMEM;
        goto ret3;
    }

    ctx->pc = pc;
    ctx->sp = sp;

    thread_t *thread;
    ret = -sched_create_thread(&thread, launch_user_thread, ctx, NULL, NULL, THREAD_USER);
    if (unlikely(ret)) goto ret4;

    thread->vmm = vmm;
    thread->namespace = ns;
    obj_ref(&vmm->base);
    obj_ref(&ns->base);

    ret = finalize_thread(proc, thread, flags);

    obj_deref(&thread->base);
ret4:
    if (unlikely(ret < 0)) vfree(ctx, sizeof(*ctx));
ret3:
    if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&vmm->base);
ret2:
    if (namespace != HYDROGEN_THIS_NAMESPACE) obj_deref(&ns->base);
ret:
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret;
}

static void clone_user_thread(void *ptr) {
    arch_context_t *ctx = ptr;
    arch_context_t context = *ctx;
    vfree(ctx, sizeof(*ctx));
    arch_context_set_syscall_return(&context, ret_integer(HYDROGEN_INVALID_HANDLE));
    arch_enter_user_mode_clone(&context);
}

hydrogen_ret_t hydrogen_thread_clone(int process, int vmm_hnd, int namespace, uint32_t flags) {
    if (unlikely((flags & ~HANDLE_FLAGS) != 0)) return ret_error(EINVAL);

    process_t *proc;
    int error = process_or_this(&proc, process, THIS_PROCESS_RIGHTS);
    if (unlikely(error)) return ret_error(error);

    namespace_t *ns;
    error = namespace_or_this(&ns, namespace, THIS_NAMESPACE_RIGHTS);
    if (unlikely(error)) goto ret;

    vmm_t *vmm;
    error = vmm_for_create(&vmm, vmm_hnd);
    if (unlikely(error)) goto ret2;

    arch_context_t *ctx = vmalloc(sizeof(*ctx));
    if (unlikely(!ctx)) {
        error = ENOMEM;
        goto ret3;
    }
    memcpy(ctx, current_thread->user_ctx, sizeof(*ctx));

    thread_t *thread;
    error = sched_create_thread(&thread, clone_user_thread, ctx, NULL, NULL, THREAD_USER);
    if (unlikely(error)) goto ret4;

    thread->vmm = vmm;
    thread->namespace = ns;
    obj_ref(&vmm->base);
    obj_ref(&ns->base);

    int handle = finalize_thread(proc, thread, flags);
    if (unlikely(handle < 0)) error = -handle;

    obj_deref(&thread->base);
ret4:
    if (unlikely(error < 0)) vfree(ctx, sizeof(*ctx));
ret3:
    if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&vmm->base);
ret2:
    if (namespace != HYDROGEN_THIS_NAMESPACE) obj_deref(&ns->base);
ret:
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return RET_MAYBE(integer, error, handle);
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
    sched_exit();
}
