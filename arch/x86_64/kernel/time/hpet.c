#include "x86_64/hpet.h"
#include "arch/mmio.h"
#include "arch/pmap.h"
#include "kernel/compiler.h"
#include "kernel/time.h"
#include "mem/kvmm.h"
#include "uacpi/acpi.h"
#include "uacpi/status.h"
#include "uacpi/tables.h"
#include "util/panic.h"
#include "util/printk.h"
#include "util/time.h"
#include "x86_64/time.h"
#include <stdint.h>

#define HPET_CAP 0x00
#define HPET_CFG 0x10
#define HPET_CNT 0xf0
#define HPET_TIMER_CFG(i) (0x100 + (i) * 0x20)
#define HPET_TIMER_CMP(i) (0x108 + (i) * 0x20)

#define HPET_CAP_COUNTER_64 (1ull << 13)

#define HPET_CFG_ENABLE (1ull << 0)

#define HPET_TIMER_CFG_IRQ_ENABLE (1ull << 2)

#define HPET_REGS_SIZE 1024

static uintptr_t hpet_regs;
static timeconv_t hpet_conv;

static uint64_t hpet_read(unsigned reg) {
    return mmio_read64(hpet_regs, reg);
}

static void hpet_write(unsigned reg, uint64_t value) {
    mmio_write64(hpet_regs, reg, value);
}

static uint64_t hpet_read_time(void) {
    return timeconv_apply(hpet_conv, hpet_read(HPET_CNT));
}

static void hpet_cleanup(void) {
    unmap_mmio(hpet_regs, HPET_REGS_SIZE);
    hpet_regs = 0;
}

static void hpet_confirm(bool final) {
    if (final && (hpet_read(HPET_CAP) & HPET_CAP_COUNTER_64) == 0) {
        panic("hpet: cannot use 32-bit hpet as system time source");
    }
}

void x86_64_hpet_init(void) {
    uacpi_table table;
    uacpi_status status = uacpi_table_find_by_signature(ACPI_HPET_SIGNATURE, &table);
    if (uacpi_unlikely_error(status)) {
        printk("hpet: no hpet table\n");
        return;
    }

    int error = map_mmio(
            &hpet_regs,
            ((struct acpi_hpet *)table.ptr)->address.address,
            HPET_REGS_SIZE,
            PMAP_READABLE | PMAP_WRITABLE | PMAP_CACHE_UC
    );
    uacpi_table_unref(&table);
    if (unlikely(error)) {
        printk("hpet: failed to map registers (%d)\n", error);
        return;
    }

    size_t cfg = hpet_read(HPET_CFG) | HPET_CFG_ENABLE;
    hpet_write(HPET_CFG, cfg & ~HPET_CFG_ENABLE);

    uint64_t cap = hpet_read(HPET_CAP);
    uint32_t hpet_period_fs = cap >> 32;
    printk("hpet: counter period is %u.%6u nanoseconds\n", hpet_period_fs / 1000000, hpet_period_fs % 1000000);

    size_t max_timer = (cap >> 8) & 0x1f;

    for (size_t i = 0; i <= max_timer; i++) {
        hpet_write(HPET_TIMER_CFG(i), hpet_read(HPET_TIMER_CFG(i)) & ~HPET_TIMER_CFG_IRQ_ENABLE);
    }

    hpet_write(HPET_CNT, 0);
    hpet_write(HPET_CFG, cfg);

    hpet_conv = timeconv_create((FS_PER_SEC + (hpet_period_fs / 2)) / hpet_period_fs, NS_PER_SEC);

    x86_64_switch_timer(hpet_read_time, NULL, hpet_cleanup, hpet_confirm);
}
