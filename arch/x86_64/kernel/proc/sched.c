#include "proc/sched.h"
#include "arch/irq.h"
#include "arch/stack.h"
#include "cpu/cpudata.h"
#include "kernel/compiler.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t rbx;
    size_t rbp;
    size_t r12;
    size_t r13;
    size_t r14;
    size_t r15;
    size_t rip;
} thread_frame_t;

extern size_t *x86_64_switch_thread(size_t *old_rsp, size_t new_rsp);
extern const void x86_64_thread_entry;

thread_t *arch_switch_thread(thread_t *from, thread_t *to) {
    irq_state_t state = save_disable_irq();

    this_cpu_write_tl(arch.tss.rsp[0], (uintptr_t)to->stack + KERNEL_STACK_SIZE);

    restore_irq(state);
    return CONTAINER(thread_t, arch.rsp, x86_64_switch_thread(&from->arch.rsp, to->arch.rsp));
}

int arch_init_thread(arch_thread_t *thread, void (*func)(void *), void *ctx, void *stack) {
    stack += KERNEL_STACK_SIZE;

    thread_frame_t *frame = stack;
    frame -= 1;
    frame->rbx = (uintptr_t)func;
    frame->r12 = (uintptr_t)ctx;
    frame->rip = (uintptr_t)&x86_64_thread_entry;

    thread->rsp = (uintptr_t)frame;
    return 0;
}

_Noreturn void x86_64_init_thread(size_t *old_rsp, void (*func)(void *), void *ctx) {
    sched_init_thread(CONTAINER(thread_t, arch.rsp, old_rsp), func, ctx);
}

void arch_reap_thread(arch_thread_t *thread) {
}
