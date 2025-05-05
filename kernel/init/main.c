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

static void kernel_init(void *ctx) {
    memmap_reclaim_loader(); // don't move below anything that can create threads, see memmap.h

    pmem_stats_t stats = pmem_get_stats();
    printk("mem: %zK total, %zK available, %zK free\n",
           stats.total * (PAGE_SIZE / 1024),
           stats.available * (PAGE_SIZE / 1024),
           stats.free * (PAGE_SIZE / 1024));
}

USED _Noreturn void kernel_main(void) {
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
    sched_wake(init_thread);
    thread_deref(init_thread);

    sched_idle();
}
