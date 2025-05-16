#include "init/main.h"
#include "arch/irq.h"
#include "cpu/cpudata.h"
#include "drv/framebuffer.h"
#include "hydrogen/memory.h"
#include "hydrogen/types.h"
#include "init/cmdline.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "limine.h"
#include "mem/memmap.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/vmm.h"
#include "proc/event.h"
#include "proc/process.h"
#include "proc/rcu.h"
#include "proc/sched.h"
#include "sections.h"
#include "sys/hydrogen.h"
#include "sys/transition.h"
#include "sys/vdso.h"
#include "util/handle.h"
#include "util/object.h"
#include "util/panic.h"
#include "util/printk.h"
#include "util/slist.h"
#include "util/spinlock.h"
#include <stddef.h>
#include <stdint.h>

__attribute__((used, section(".requests0"))) static LIMINE_REQUESTS_START_MARKER;
__attribute__((used, section(".requests2"))) static LIMINE_REQUESTS_END_MARKER;

LIMINE_REQ LIMINE_BASE_REVISION(3);

#define USER_STACK_SIZE 0x800000

static slist_t kernel_tasks;
static thread_t *task_thread;
static spinlock_t kernel_tasks_lock;

static void launch_init_process(void *ctx) {
    int error = namespace_create(&current_thread->namespace);
    if (unlikely(error)) panic("failed to create init process namespace (%e)", error);

    error = vmm_create(&current_thread->vmm);
    if (unlikely(error)) panic("failed to create init process vmm (%e)", error);
    vmm_switch(current_thread->vmm);

    hydrogen_ret_t ret = setsid(current_thread->process);
    if (unlikely(ret.error)) panic("failed to create init session (%e)", ret.error);

    ret = vmm_map_vdso(current_thread->vmm);
    if (unlikely(ret.error)) panic("failed to map vdso (%e)", ret.error);
    uintptr_t vdso_base = ret.integer;

    ret = vmm_map(current_thread->vmm, 0, USER_STACK_SIZE + PAGE_SIZE, HYDROGEN_MEM_LAZY_RESERVE, NULL, 0, 0);
    if (unlikely(ret.error)) panic("failed to allocate stack area (%e)", ret.error);
    uintptr_t stack_base = ret.integer + PAGE_SIZE;

    error = vmm_remap(current_thread->vmm, stack_base, USER_STACK_SIZE, HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE);
    if (unlikely(error)) panic("failed to make stack writable (%e)", error);

    arch_enter_user_mode_init(vdso_base + vdso_image.entry, stack_base, USER_STACK_SIZE);
}

// this is in a separate function so that kernel_init can be INIT_TEXT
__attribute__((noinline)) static _Noreturn void finalize_init(void) {
    memmap_reclaim_init();

    pmem_stats_t stats = pmem_get_stats();
    printk("mem: %zK total, %zK available, %zK free\n",
           stats.total * (PAGE_SIZE / 1024),
           stats.available * (PAGE_SIZE / 1024),
           stats.free * (PAGE_SIZE / 1024));

    int error = proc_clone(&init_process);
    if (unlikely(error)) panic("failed to create init process (%e)", error);

    thread_t *thread;
    error = sched_create_thread(&thread, launch_init_process, NULL, NULL, init_process, THREAD_USER);
    if (unlikely(error)) panic("failed to create init process main thread (%d)", error);

    task_thread = current_thread;
    sched_wake(thread);
    obj_deref(&thread->base);

    for (;;) {
        irq_state_t state = spin_acq(&kernel_tasks_lock);
        task_t *task = SLIST_REMOVE_HEAD(kernel_tasks, task_t, node);
        if (!task) sched_prepare_wait(false);
        spin_rel(&kernel_tasks_lock, state);
        if (!task) {
            sched_perform_wait(0);
            continue;
        }

        task->func(task);
    }
}

INIT_TEXT static void kernel_init(void *ctx) {
    memmap_reclaim_loader(); // don't move below anything that can create threads, see memmap.h
    sched_init_late();
    arch_init_late();
    vdso_init();
    host_name_init();
    // the idle thread still holds a reference to this thread, but it can't free it itself because that might sleep
    obj_deref(&current_thread->base);
    finalize_init();
}

// this is in a separate function so that kernel_main can be INIT_TEXT
__attribute__((noinline)) static _Noreturn void wake_init_thread_and_idle(thread_t *thread) {
    sched_wake(thread);
    sched_idle();
}

INIT_TEXT USED _Noreturn void kernel_main(void) {
    parse_command_line();
    sched_init();
    rcu_init();
    memmap_init();
    fb_init();

    if (!LIMINE_BASE_REVISION_SUPPORTED) {
        panic("loader does not support requested base revision");
    }

    arch_init_early();
    time_init();
    proc_init();

    thread_t *init_thread;
    int error = sched_create_thread(&init_thread, kernel_init, NULL, NULL, &kernel_process, 0);
    if (unlikely(error)) panic("failed to create init thread (%e)", error);
    wake_init_thread_and_idle(init_thread);
}

// this is in a separate function so that smp_init_current can be INIT_TEXT
__attribute__((noinline)) static _Noreturn void signal_and_idle(event_t *event) {
    if (event != NULL) event_signal(event);
    sched_idle();
}

INIT_TEXT _Noreturn void smp_init_current(event_t *event, void *ctx) {
    sched_init();
    rcu_init();
    pmap_init_switch();
    arch_init_current(ctx);
    signal_and_idle(event);
}

INIT_TEXT void smp_init_current_late(void) {
    sched_init_late();
}

void schedule_kernel_task(task_t *task) {
    irq_state_t state = spin_acq(&kernel_tasks_lock);
    slist_insert_tail(&kernel_tasks, &task->node);
    spin_rel(&kernel_tasks_lock, state);
}
