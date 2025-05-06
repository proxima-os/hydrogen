#include "init/main.h"
#include "drv/framebuffer.h"
#include "init/cmdline.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "limine.h"
#include "mem/memmap.h"
#include "mem/pmem.h"
#include "proc/rcu.h"
#include "proc/sched.h"
#include "sections.h"
#include "util/panic.h"
#include "util/printk.h"
#include <stddef.h>

__attribute__((used, section(".requests0"))) static LIMINE_REQUESTS_START_MARKER;
__attribute__((used, section(".requests2"))) static LIMINE_REQUESTS_END_MARKER;

LIMINE_REQ LIMINE_BASE_REVISION(3);

// this is in a separate function so that kernel_init can be INIT_TEXT
__attribute__((noinline)) static _Noreturn void finalize_init(void) {
    memmap_reclaim_init();

    pmem_stats_t stats = pmem_get_stats();
    printk("mem: %zK total, %zK available, %zK free\n",
           stats.total * (PAGE_SIZE / 1024),
           stats.available * (PAGE_SIZE / 1024),
           stats.free * (PAGE_SIZE / 1024));
    sched_exit();
}

INIT_TEXT static void kernel_init(void *ctx) {
    memmap_reclaim_loader(); // don't move below anything that can create threads, see memmap.h
    finalize_init();
}

// this is in a separate function so that kernel_main can be INIT_TEXT
__attribute__((noinline)) static _Noreturn void wake_init_thread_and_idle(thread_t *thread) {
    sched_wake(thread);
    thread_deref(thread);
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

    arch_init();

    thread_t *init_thread;
    int error = sched_create_thread(&init_thread, kernel_init, NULL);
    if (unlikely(error)) panic("failed to create init thread (%d)", error);
    wake_init_thread_and_idle(init_thread);
}
