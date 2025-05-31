#include "x86_64/pit.h"
#include "arch/irq.h"
#include "arch/pio.h"
#include "drv/interrupt.h"
#include "kernel/compiler.h"
#include "kernel/time.h"
#include "util/panic.h"
#include "util/printk.h"
#include "util/spinlock.h"
#include "util/time.h"
#include "x86_64/ioapic.h"
#include "x86_64/time.h"
#include <hydrogen/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// The PIT cannot be enumerated without AML, so instead we just don't touch it until pit_confirm is called. Systems
// without it should have initialized another timer (such as HPET) by then.

#define PIT_FREQ 1193182
#define PIT_VALUE 0x10000 // written to registers as 0000, but the hw interprets this correctly

#define PIT_CH0 0x40
#define PIT_MODE 0x43

#define PIT_MODE_RATE (2 << 1)
#define PIT_ACCESS_BOTH (3 << 4)

static uint64_t pit_ticks;
static void *pit_irq;
static spinlock_t pit_lock;
static timeconv_t pit_conv;

static uint64_t pit_read(void) {
    static uint64_t last_ticks;
    static uint16_t last_count = UINT16_MAX;

    irq_state_t state = spin_acq(&pit_lock);

    uint64_t ticks = pit_ticks;
    pio_write8(PIT_MODE, 0);
    uint16_t count = pio_read8(PIT_CH0);
    count |= (uint16_t)pio_read8(PIT_CH0) << 8;

    if (count > last_count && ticks == last_ticks) count = last_count;

    last_count = count;
    last_ticks = ticks;

    spin_rel(&pit_lock, state);

    count = (PIT_VALUE - 1) - count;
    return timeconv_apply(pit_conv, (ticks * PIT_VALUE) + count);
}

static void handle_pit_irq(void *ctx) {
    spin_acq_noirq(&pit_lock);
    pit_ticks += 1;
    spin_rel_noirq(&pit_lock);
}

static void pit_cleanup(void) {
    if (pit_irq) {
        pio_write8(PIT_MODE, PIT_ACCESS_BOTH);
        pio_write8(PIT_CH0, 0);
        pio_write8(PIT_CH0, 0);
        pio_write8(PIT_MODE, PIT_ACCESS_BOTH);
        x86_64_isa_controller.ops->close(&x86_64_isa_controller, pit_irq);
    }
}

static void pit_confirm(bool final) {
    if (!pit_irq) {
        pit_conv = timeconv_create(PIT_FREQ, NS_PER_SEC);

        hydrogen_ret_t irq = x86_64_isa_controller.ops->open(
            &x86_64_isa_controller,
            0,
            IRQ_ACTIVE_HIGH | IRQ_EDGE_TRIGGERED,
            handle_pit_irq,
            NULL
        );
        if (unlikely(irq.error)) panic("pit: failed to open interrupt (%e)", irq.error);
        pit_irq = irq.pointer;

        pio_write8(PIT_MODE, PIT_ACCESS_BOTH | PIT_MODE_RATE);
        pio_write8(PIT_CH0, PIT_VALUE & 0xff);
        pio_write8(PIT_CH0, (PIT_VALUE >> 8) & 0xff);

        x86_64_isa_controller.ops->unmask(&x86_64_isa_controller, pit_irq);
        printk("pit: initialized\n");
    }

    if (final) {
        printk("pit: using pit as system time source, this can lead to extreme slowdown due to high access times\n");
    }
}

void x86_64_pit_init(void) {
    x86_64_switch_timer(pit_read, NULL, pit_cleanup, pit_confirm);
}
