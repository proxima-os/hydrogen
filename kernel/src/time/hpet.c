#include "time/hpet.h"
#include "asm/irq.h"
#include "asm/mmio.h"
#include "drv/acpi.h"
#include "hydrogen/memory.h"
#include "kernel/compiler.h"
#include "kernel/time.h"
#include "mem/kvmm.h"
#include "time/time.h"
#include "util/logging.h"
#include "util/spinlock.h"
#include <stdint.h>

#define HPET_CAP 0
#define HPET_CFG 0x10
#define HPET_COUNTER 0xf0
#define HPET_TIMER_CFG(i) (0x100 + (i) * 0x20)
#define HPET_REGS_SIZE 1024

#define HPET_CAP_64 (1ul << 13)
#define HPET_CFG_ENABLE 1
#define HPET_TIMER_CFG_ENABLE_INTERRUPT 4

static void *hpet_regs;
static timeconv_t hpet_conv;

static uint64_t hpet_offset;
static uint64_t hpet_last;
static spinlock_t hpet_lock;

static uint64_t hpet_read64(void) {
    return timeconv_apply(hpet_conv, mmio_read64(hpet_regs, HPET_COUNTER));
}

static uint64_t hpet_read32_unlocked(void) {
    uint64_t raw_value = mmio_read64(hpet_regs, HPET_COUNTER);
    if (raw_value < hpet_last) hpet_offset += 0x100000000;
    raw_value += hpet_offset;

    return timeconv_apply(hpet_conv, raw_value);
}

static uint64_t hpet_read32(void) {
    irq_state_t state = spin_lock(&hpet_lock);
    uint64_t value = hpet_read32_unlocked();
    restore_irq(state);
    return value;
}

static void hpet_cleanup(void) {
    irq_state_t state = spin_lock(&hpet_lock);
    unmap_phys_mem(hpet_regs, HPET_REGS_SIZE);
    hpet_regs = NULL;
    spin_unlock(&hpet_lock, state);
}

void init_hpet(void) {
    const acpi_hpet_t *hpet_table = (const acpi_hpet_t *)get_acpi_table("HPET");
    if (unlikely(!hpet_table)) {
        printk("hpet: acpi table not found\n");
        return;
    }

    int error = map_phys_mem(
            &hpet_regs,
            hpet_table->base.address,
            HPET_REGS_SIZE,
            HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE | HYDROGEN_MEM_NO_CACHE
    );
    if (unlikely(error)) {
        printk("hpet: failed to map registers at 0x%X (%d)", hpet_table->base.address, error);
        return;
    }

    uint64_t cap = mmio_read64(hpet_regs, HPET_CAP);
    uint64_t cfg = mmio_read64(hpet_regs, HPET_CFG);
    mmio_write64(hpet_regs, HPET_CFG, cfg & ~HPET_CFG_ENABLE);
    mmio_write64(hpet_regs, HPET_COUNTER, 0);

    uint32_t period = cap >> 32;
    unsigned timers = (cap >> 8) & 0x1f;

    for (unsigned i = 0; i <= timers; i++) {
        mmio_write64(
                hpet_regs,
                HPET_TIMER_CFG(i),
                mmio_read64(hpet_regs, HPET_TIMER_CFG(i) & ~HPET_TIMER_CFG_ENABLE_INTERRUPT)
        );
    }

    mmio_write64(hpet_regs, HPET_CFG, cfg | HPET_CFG_ENABLE);

    uint64_t frequency = (FS_PER_SEC + (period / 2)) / period;
    hpet_conv = create_timeconv(frequency, NS_PER_SEC);

    if (cap & HPET_CAP_64) {
        read_time = hpet_read64;
        read_time_unlocked = hpet_read64;
    } else {
        read_time = hpet_read32;
        read_time_unlocked = hpet_read32_unlocked;
    }

    timer_cleanup = hpet_cleanup;
    printk("time: hpet is available\n");
}
