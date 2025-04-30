#include "thread/sched.h"
#include "asm/idle.h"
#include "asm/irq.h"
#include "asm/msr.h"
#include "asm/segreg.h"
#include "cpu/cpu.h"
#include "cpu/idt.h"
#include "cpu/irqvecs.h"
#include "cpu/lapic.h"
#include "cpu/xsave.h"
#include "errno.h"
#include "hydrogen/handle.h"
#include "hydrogen/thread.h"
#include "hydrogen/time.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/layout.h"
#include "mem/pmap.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "string.h"
#include "sys/syscall.h"
#include "thread/mutex.h"
#include "time/time.h"
#include "util/handle.h"
#include "util/object.h"
#include "util/panic.h"
#include "util/spinlock.h"
#include <stdint.h>

#define TIMESLICE_LEN_NS (10000000ul) /* 10ms */

#define current_sched (current_cpu.sched)
#define current_sched_ptr (&current_cpu_ptr->sched)

extern thread_regs_t **switch_thread(thread_regs_t **from, thread_regs_t *to);

extern void fillfb(uint32_t color);

static void do_yield(sched_t *sched);

static void maybe_preempt(sched_t *sched) {
    if (sched->current == &sched->idle && sched->queue.first != NULL) {
        if (sched == current_sched_ptr) {
            do_yield(sched);
        } else {
            cpu_t *cpu = (void *)sched - offsetof(cpu_t, sched);
            send_ipi(VEC_IPI_YIELD, cpu);
        }
    }
}

static void handle_ipi_yield(UNUSED idt_frame_t *frame, UNUSED void *ctx) {
    sched_t *sched = current_sched_ptr;
    sched_disable_preempt();
    spin_lock_noirq(&sched->queue.lock);
    maybe_preempt(sched);
    spin_unlock_noirq(&sched->queue.lock);
    lapic_eoi();
    sched_enable_preempt();
}

void init_sched_global(void) {
    idt_install(VEC_IPI_YIELD, handle_ipi_yield, NULL);
}

static void switch_handler(timer_event_t *event);

void init_sched_early(void) {
    sched_t *sched = current_sched_ptr;
    sched->current = &sched->idle;
    sched->current->state = THREAD_RUNNING;
    sched->current->sched = sched;
    event_init(&sched->switch_event, switch_handler);
}

static void reap_thread(thread_t *thread) {
    __atomic_fetch_sub(&thread->sched->threads, 1, __ATOMIC_RELAXED);
    free_kernel_stack(thread->stack);
    xsave_free(thread->xsave);

    if (thread->address_space) {
        obj_deref(&thread->address_space->base);
    }

    if (thread->namespace) {
        obj_deref(&thread->namespace->base);
    }

    thread->state = THREAD_EXITED;
}

static void reaper_func(UNUSED void *ctx) {
    sched_t *sched = current_sched_ptr;

    for (;;) {
        irq_state_t state = save_disable_irq();
        if (sched->reap_queue == NULL) sched_wait(0, NULL);
        thread_t *thread = sched->reap_queue;
        sched->reap_queue = thread->next;
        restore_irq(state);

        ASSERT(thread->state == THREAD_EXITING);
        reap_thread(thread);
        obj_deref(&thread->base);
    }
}

void init_sched_late(void) {
    int error = sched_create(&current_sched_ptr->reaper, reaper_func, NULL, current_cpu_ptr);
    if (unlikely(error)) panic("failed to create reaper thread (%d)", error);
}

_Noreturn void sched_idle(void) {
    enable_irq();
    for (;;) cpu_idle();
}

static void thread_free(object_t *ptr) {
    thread_t *self = (thread_t *)ptr;

    if (self->state == THREAD_CREATED) {
        reap_thread(self);
    }

    ASSERT(self->state == THREAD_EXITED);
    vmfree(self, sizeof(*self));
}

static const object_ops_t thread_ops = {.free = thread_free};

extern const void new_thread_thunk;

static void enqueue(sched_t *sched, thread_t *thread) {
    if (sched->queue.first) sched->queue.last->next = thread;
    else sched->queue.first = thread;

    sched->queue.last = thread;
    thread->next = NULL;
}

static void do_wake(sched_t *sched, thread_t *thread, wake_reason_t reason) {
    ASSERT(sched == thread->sched);
    thread->wake_reason = reason;

    if (thread->state == THREAD_CREATED) {
        thread->state = THREAD_WAITING;
        obj_ref(&thread->base);
    }

    if (thread->state == THREAD_WAITING) {
        thread->state = THREAD_RUNNING;
        if (reason != WAKE_TIMEOUT) cancel_event(&thread->timeout_event);

        enqueue(sched, thread);
        maybe_preempt(sched);
    }
}

static void handle_timeout(timer_event_t *event) {
    thread_t *thread = (void *)event - offsetof(thread_t, timeout_event);
    sched_t *sched = thread->sched;

    irq_state_t state = spin_lock(&sched->queue.lock);
    do_wake(sched, thread, WAKE_TIMEOUT);
    spin_unlock(&sched->queue.lock, state);
}

int sched_create(thread_t **out, thread_func_t func, void *ctx, cpu_t *cpu) {
    thread_t *thread = vmalloc(sizeof(*thread));
    if (unlikely(!thread)) return ENOMEM;

    void *stack = alloc_kernel_stack();
    if (unlikely(!stack)) {
        vmfree(thread, sizeof(*thread));
        return ENOMEM;
    }

    void *xsave = xsave_alloc();
    if (unlikely(!xsave)) {
        free_kernel_stack(stack);
        vmfree(thread, sizeof(*thread));
        return ENOMEM;
    }

    memset(thread, 0, sizeof(*thread));
    obj_init(&thread->base, &thread_ops);
    thread->state = THREAD_CREATED;
    thread->regs = stack - sizeof(thread_regs_t);
    thread->stack = stack;
    thread->xsave = xsave;
    thread->address_space = NULL;
    event_init(&thread->timeout_event, handle_timeout);
    thread->timeslice_rem = TIMESLICE_LEN_NS;

    thread->regs->rbx = (uintptr_t)func;
    thread->regs->r12 = (uintptr_t)ctx;
    thread->regs->rip = (uintptr_t)&new_thread_thunk;

    if (!cpu) {
        size_t cur_count = SIZE_MAX;

        for (cpu_t *cur = cpus; cur != NULL; cur = cur->next) {
            size_t count = __atomic_load_n(&cur->sched.threads, __ATOMIC_RELAXED);

            if (count < cur_count) {
                cpu = cur;
                cur_count = count;
            }
        }

        ASSERT(cpu != NULL);
    }

    thread->sched = &cpu->sched;
    __atomic_fetch_add(&cpu->sched.threads, 1, __ATOMIC_RELAXED);

    *out = thread;
    return 0;
}

static void post_switch_func(sched_t *sched, thread_regs_t **prev_regs) {
    ASSERT(sched == current_sched_ptr);
    thread_t *prev = (void *)prev_regs - offsetof(thread_t, regs);

    current_cpu.tss.rsp[0] = (uintptr_t)current_thread->stack;
    xrestore();
    pmap_switch(current_thread->address_space ? &current_thread->address_space->pmap : NULL);

    if (current_thread->ds != prev->ds) write_ds(current_thread->ds);
    if (current_thread->es != prev->es) write_es(current_thread->es);
    if (current_thread->fs != prev->fs) write_fs(current_thread->fs);
    if (current_thread->gs != prev->gs) write_gs_swapgs_wrapped(current_thread->gs);

    if (current_thread->fs != prev->fs || current_thread->fsbase != prev->fsbase) {
        wrmsr(MSR_FS_BASE, current_thread->fsbase);
    }

    if (current_thread->gs != prev->gs || current_thread->gsbase != prev->gsbase) {
        wrmsr(MSR_KERNEL_GS_BASE, current_thread->gsbase);
    }

    if (prev->sched != sched) {
        // finish prev's migration
        maybe_preempt(prev->sched);
        spin_unlock_noirq(&prev->sched->queue.lock);
    }
}

static void do_yield(sched_t *sched) {
    ASSERT(sched == current_sched_ptr);

    thread_t *current = sched->current;
    thread_t *next;

    if (sched->preempt != 0) {
        __atomic_store_n(&current->preempted, true, __ATOMIC_RELAXED);
        return;
    }

    __atomic_store_n(&current->preempted, false, __ATOMIC_RELAXED);

    uint64_t time = hydrogen_get_time();
    uint64_t diff = time - sched->switch_time;
    sched->switch_time = time;

    if (diff >= current->timeslice_rem) {
        current->timeslice_rem = TIMESLICE_LEN_NS;
    } else {
        current->timeslice_rem -= diff;
    }

    if (sched->queue.first) {
        next = sched->queue.first;
        sched->queue.first = next->next;

        if (current->state == THREAD_RUNNING && current->sched == sched && current != &sched->idle) {
            enqueue(sched, current);
        }
    } else if (current->state == THREAD_RUNNING && current->sched == sched) {
        next = current;
    } else {
        next = &sched->idle;
    }

    cancel_event(&sched->switch_event);

    if (next != &sched->idle) {
        sched->switch_event.time = time + next->timeslice_rem;
        //queue_event(&sched->switch_event);
    }

    if (current == next) return;

    xsave();
    current->ds = read_ds();
    current->es = read_es();
    current->fs = read_fs();
    current->gs = read_gs();
    current->fsbase = rdmsr(MSR_FS_BASE);
    current->gsbase = rdmsr(MSR_KERNEL_GS_BASE);

    sched->current = next;
    post_switch_func(current->sched, switch_thread(&current->regs, next->regs));
}

static void switch_handler(UNUSED timer_event_t *event) {
    sched_t *sched = current_sched_ptr;
    spin_lock_noirq(&sched->queue.lock);

    if (current_thread->state == THREAD_RUNNING) {
        do_yield(sched);
    }

    spin_unlock_noirq(&sched->queue.lock);
}

_Noreturn void sched_init_thread(thread_regs_t **prev_regs, thread_func_t func, void *ctx) {
    sched_t *sched = current_sched_ptr;
    post_switch_func(sched, prev_regs);
    spin_unlock_noirq(&sched->queue.lock);
    enable_irq();

    func(ctx);
    hydrogen_thread_exit();
}

void sched_yield(void) {
    sched_t *sched = current_sched_ptr;
    irq_state_t state = spin_lock(&sched->queue.lock);

    ASSERT(current_sched.preempt == 0);
    do_yield(sched);

    spin_unlock(&sched->queue.lock, state);
}

void sched_disable_preempt(void) {
    asm volatile("incl %0" : "+m"(current_sched.preempt));
}

void sched_enable_preempt(void) {
    bool zero;
    asm volatile("decl %0" : "+m"(current_sched.preempt), "=@ccz"(zero));

    if (zero && __atomic_load_n(&current_thread->preempted, __ATOMIC_RELAXED)) {
        sched_yield();
    }
}

void sched_migrate(cpu_t *dest) {
    sched_t *src = current_sched_ptr;
    thread_t *thread = src->current;
    ASSERT(thread != &src->idle);

    // dest->sched.queue.lock is unlocked in the do_yield call, so it has to be locked after src->queue.lock
    irq_state_t state = spin_lock(&src->queue.lock);
    spin_lock_noirq(&dest->sched.queue.lock);

    __atomic_fetch_sub(&src->threads, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&dest->sched.threads, 1, __ATOMIC_RELAXED);

    thread->sched = &dest->sched;
    enqueue(&dest->sched, thread);

    // the thread this switches to unlocks dest->sched.queue.lock and src->queue.lock.
    // when the target cpu yields to this thread, it relocks dest->sched.queue.lock, so we still have to unlock that.
    do_yield(src);
    spin_unlock(&dest->sched.queue.lock, state);
}

void sched_wake(thread_t *thread) {
    sched_t *sched = thread->sched;
    irq_state_t state = spin_lock(&sched->queue.lock);
    do_wake(sched, thread, WAKE_EXPLICIT);
    spin_unlock(&sched->queue.lock, state);
}

int sched_wait(uint64_t timeout, spinlock_t *lock) {
    sched_t *sched = current_sched_ptr;
    thread_t *thread = sched->current;
    ASSERT(thread != &sched->idle);

    irq_state_t state = spin_lock(&sched->queue.lock);

    if (timeout) {
        thread->timeout_event.time = timeout;
        queue_event(&thread->timeout_event);
    }

    thread->state = THREAD_WAITING;

    if (lock) spin_unlock_noirq(lock);

    ASSERT(current_sched.preempt == 0);
    do_yield(sched);

    spin_unlock(&sched->queue.lock, state);
    if (lock) spin_lock_noirq(lock);

    switch (thread->wake_reason) {
    case WAKE_EXPLICIT: return 0;
    case WAKE_TIMEOUT: return ETIMEDOUT;
    default: __builtin_unreachable();
    }
}

__attribute__((__noreturn__)) void hydrogen_thread_exit(void) {
    sched_t *sched = current_sched_ptr;
    thread_t *thread = sched->current;
    ASSERT(thread != &sched->idle);

    spin_lock(&sched->queue.lock);

    ASSERT(sched->preempt == 0);
    thread->state = THREAD_EXITING;

    thread->next = sched->reap_queue;
    sched->reap_queue = thread;

    // The do_wake call here might yield, but that's fine since we don't need it to return.
    do_wake(sched, sched->reaper, WAKE_EXPLICIT);
    do_yield(sched);
    __builtin_unreachable();
}

void *alloc_kernel_stack(void) {
    void *ptr = vmalloc(KERNEL_STACK_SIZE);
    if (unlikely(!ptr)) return NULL;
    return ptr + KERNEL_STACK_SIZE;
}

void free_kernel_stack(void *stack) {
    vmfree(stack - KERNEL_STACK_SIZE, KERNEL_STACK_SIZE);
}

#define THREAD_NS_RIGHTS                                                                                 \
    (HYDROGEN_NAMESPACE_RIGHT_CREATE | HYDROGEN_NAMESPACE_RIGHT_CLOSE | HYDROGEN_NAMESPACE_RIGHT_CLONE | \
     HYDROGEN_NAMESPACE_RIGHT_RESOLVE)
#define THREAD_VM_RIGHTS                                                                                   \
    (HYDROGEN_VM_RIGHT_MAP | HYDROGEN_VM_RIGHT_REMAP | HYDROGEN_VM_RIGHT_UNMAP | HYDROGEN_VM_RIGHT_CLONE | \
     HYDROGEN_VM_RIGHT_WRITE | HYDROGEN_VM_RIGHT_READ)

static void launch_user_thread(void *ctx) {
    enter_user_mode((uintptr_t)ctx, (uintptr_t)current_thread->user_regs);
}

hydrogen_ret_t hydrogen_thread_create(hydrogen_handle_t namespace, hydrogen_handle_t vm_handle, void *pc, void *sp) {
    if (unlikely(!is_address_canonical((uintptr_t)pc))) return RET_ERROR(EINVAL);

    namespace_t *ns;
    int error = get_ns(namespace, &ns, THREAD_NS_RIGHTS);
    if (unlikely(error)) return RET_ERROR(error);

    address_space_t *vm;
    error = get_vm(vm_handle, &vm, THREAD_VM_RIGHTS);
    if (unlikely(error)) goto ret;

    thread_t *thread;
    error = sched_create(&thread, launch_user_thread, pc, NULL);
    if (unlikely(error)) goto ret2;

    thread->address_space = vm;
    thread->namespace = ns;
    thread->user_regs = sp;

    obj_ref(&vm->base);
    obj_ref(&ns->base);

    hydrogen_handle_t handle;
    error = create_handle(&thread->base, -1, &handle);
    if (unlikely(error)) goto ret3;

    sched_wake(thread);
ret3:
    obj_deref(&thread->base);
ret2:
    if (vm_handle) obj_deref(&vm->base);
ret:
    if (namespace) obj_deref(&ns->base);
    return RET_HANDLE_MAYBE(error, handle);
}

int hydrogen_thread_reinit(hydrogen_handle_t namespace, hydrogen_handle_t vm_handle, void *pc, void *sp) {
    if (unlikely(!is_address_canonical((uintptr_t)pc))) return EINVAL;

    namespace_t *ns;
    int error = get_ns(namespace, &ns, THREAD_NS_RIGHTS);
    if (unlikely(error)) return error;

    address_space_t *vm;
    error = get_vm(vm_handle, &vm, THREAD_VM_RIGHTS);
    if (unlikely(error)) {
        if (namespace) obj_deref(&ns->base);
        return error;
    }

    obj_deref(&current_thread->namespace->base);
    current_thread->namespace = ns;
    vm_switch(vm);
    enter_user_mode((uintptr_t)pc, (uintptr_t)sp);
}

static void launch_cloned_thread(void *ptr) {
    idt_frame_t *ctx = ptr;
    idt_frame_t regs = *ctx;
    vmfree(ctx, sizeof(*ctx));

    regs.rax = 0;
    regs.rdx = 0;
    return_from_fork(&regs);
}

hydrogen_ret_t hydrogen_thread_clone(hydrogen_handle_t namespace, hydrogen_handle_t vm_handle) {
    namespace_t *ns;
    int error = get_ns(namespace, &ns, THREAD_NS_RIGHTS);
    if (unlikely(error)) return RET_ERROR(error);

    address_space_t *vm;
    error = get_vm(vm_handle, &vm, THREAD_VM_RIGHTS);
    if (unlikely(error)) goto ret;

    idt_frame_t *regs = vmalloc(sizeof(*regs));
    if (unlikely(!regs)) goto ret2;
    memcpy(regs, current_thread->user_regs, sizeof(*regs));

    thread_t *thread;
    error = sched_create(&thread, launch_cloned_thread, regs, NULL);
    if (unlikely(error)) {
        vmfree(regs, sizeof(*regs));
        goto ret2;
    }

    thread->address_space = vm;
    thread->namespace = ns;
    // don't need to copy xsave state, since the default for a newly created thread is cloned from the creator
    thread->ds = read_ds();
    thread->es = read_es();
    thread->fs = read_fs();
    thread->gs = read_gs();
    thread->fsbase = rdmsr(MSR_FS_BASE);
    thread->gsbase = rdmsr(MSR_KERNEL_GS_BASE);

    obj_ref(&vm->base);
    obj_ref(&ns->base);

    hydrogen_handle_t handle;
    error = create_handle(&thread->base, -1, &handle);
    if (unlikely(error)) {
        vmfree(regs, sizeof(*regs));
        goto ret3;
    }

    sched_wake(thread);
ret3:
    obj_deref(&thread->base);
ret2:
    if (vm_handle) obj_deref(&vm->base);
ret:
    if (namespace) obj_deref(&ns->base);
    return RET_HANDLE_MAYBE(error, handle);
}

void hydrogen_thread_yield(void) {
    sched_yield();
}

uintptr_t hydrogen_x86_64_get_fs_base(void) {
    return rdmsr(MSR_FS_BASE);
}

uintptr_t hydrogen_x86_64_get_gs_base(void) {
    return rdmsr(MSR_KERNEL_GS_BASE);
}

int hydrogen_x86_64_set_fs_base(uintptr_t address) {
    if (unlikely(!is_address_canonical(address))) return EINVAL;
    wrmsr(MSR_FS_BASE, address);
    return 0;
}

int hydrogen_x86_64_set_gs_base(uintptr_t address) {
    if (unlikely(!is_address_canonical(address))) return EINVAL;
    wrmsr(MSR_KERNEL_GS_BASE, address);
    return 0;
}
