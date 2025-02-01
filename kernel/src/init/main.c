#include "asm/idle.h"
#include "asm/irq.h"
#include "cpu/cpu.h"
#include "cpu/exc.h"
#include "cpu/idt.h"
#include "cpu/lapic.h"
#include "drv/acpi.h"
#include "drv/pic.h"
#include "kernel/compiler.h"
#include "limine.h"
#include "mem/pmm.h"
#include "sections.h"
#include "time/time.h"
#include "util/logging.h"

__attribute__((used, section(".requests0"))) static LIMINE_REQUESTS_START_MARKER;
__attribute__((used, section(".requests2"))) static LIMINE_REQUESTS_END_MARKER;

LIMINE_REQ LIMINE_BASE_REVISION(3);

USED _Noreturn void kernel_main(void) {
    detect_cpu_features();
    init_idt();
    init_exceptions();
    init_cpu(NULL);
    init_pmm();
    init_acpi();
    reclaim_loader_pages();
    init_lapic_bsp();
    init_lapic();
    init_pic();
    enable_irq();
    init_time();

    pmm_stats_t stats = pmm_get_stats();
    printk("mem: %Uk total, %Uk available, %Uk free\n",
           stats.total << (PAGE_SHIFT - 10),
           stats.available << (PAGE_SHIFT - 10),
           stats.free << (PAGE_SHIFT - 10));

    for (;;) cpu_idle();
}
