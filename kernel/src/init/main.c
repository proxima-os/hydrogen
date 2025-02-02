#include "cpu/cpu.h"
#include "cpu/exc.h"
#include "cpu/idt.h"
#include "cpu/lapic.h"
#include "cpu/xsave.h"
#include "drv/acpi.h"
#include "drv/pic.h"
#include "hydrogen/error.h"
#include "kernel/compiler.h"
#include "limine.h"
#include "mem/pmm.h"
#include "sections.h"
#include "thread/sched.h"
#include "time/time.h"
#include "util/logging.h"
#include "util/object.h"
#include "util/panic.h"
#include <stdint.h>

__attribute__((used, section(".requests0"))) static LIMINE_REQUESTS_START_MARKER;
__attribute__((used, section(".requests2"))) static LIMINE_REQUESTS_END_MARKER;

LIMINE_REQ LIMINE_BASE_REVISION(3);

static void kernel_init(UNUSED void *ctx) {
    init_sched_late();
    init_smp();
    reclaim_loader_pages();

    pmm_stats_t stats = pmm_get_stats();
    printk("mem: %Uk total, %Uk available, %Uk free\n",
           stats.total << (PAGE_SHIFT - 10),
           stats.available << (PAGE_SHIFT - 10),
           stats.free << (PAGE_SHIFT - 10));
}

USED _Noreturn void kernel_main(void) {
    detect_cpu_features();
    init_idt();
    init_exceptions();
    init_cpu(NULL);
    init_pmm();
    init_fb_log();
    init_acpi();
    init_lapic_bsp();
    init_lapic();
    init_pic();
    init_time();
    init_time_local();
    init_sched_global();
    init_sched_early();
    init_xsave();

    thread_t *init_thread;
    hydrogen_error_t error = sched_create(&init_thread, kernel_init, NULL, NULL);
    if (unlikely(error)) panic("failed to create init thread (%d)", error);
    sched_wake(init_thread);
    obj_deref(&init_thread->base);

    sched_idle();
}
