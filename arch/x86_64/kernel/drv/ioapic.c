#include "x86_64/ioapic.h"
#include "arch/gsi.h"
#include "arch/irq.h"
#include "arch/mmio.h"
#include "arch/pio.h"
#include "arch/pmap.h"
#include "cpu/cpudata.h"
#include "drv/acpi/acpi.h" /* IWYU pragma: keep */
#include "drv/interrupt.h"
#include "errno.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/kvmm.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "uacpi/acpi.h"
#include "uacpi/status.h"
#include "uacpi/tables.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/printk.h"
#include "util/slist.h"
#include "util/spinlock.h"
#include "x86_64/idtvec.h"
#include "x86_64/lapic.h"
#include <hydrogen/fcntl.h>
#include <hydrogen/ioctl-data.h>
#include <hydrogen/ioctl.h>
#include <hydrogen/types.h>
#include <stdbool.h>
#include <stdint.h>

#define IOAPICID 0
#define IOAPICVER 1
#define IOREDTBL(i) (0x10 + (i) * 2)

#define IOAPIC_NMI (4u << 8)
#define IOAPIC_ACTIVE_LOW (1u << 13)
#define IOAPIC_LEVEL_TRIGGERED (1u << 15)
#define IOAPIC_MASKED (1u << 16)

typedef struct ioapic ioapic_t;

typedef struct {
    hlist_t handlers;
    size_t count;
    size_t masks;
    irq_t irq;
    spinlock_t lock;
    bool has_isa_irq : 1;
    bool active_low : 1;
    bool level_triggered : 1;
    bool shareable : 1;
} ioapic_pin_t;

typedef struct {
    interrupt_t base;
    ioapic_t *apic;
    ioapic_pin_t *pin;
} ioapic_irq_t;

struct ioapic {
    slist_node_t node;
    uintptr_t regs;
    uint32_t gsi_base;
    uint32_t num_pins;
    ioapic_pin_t *pins;
    spinlock_t lock;
};

static struct {
    uint32_t gsi;
    int flags;
} isa_irq_overrides[16];

_Static_assert(((X86_64_IDT_LAPIC_SPURIOUS - 7) & 7) == 0, "Spurious IRQ must have the 3 lowest bits set");

static slist_t ioapics;
static bool have_8259;

static uint32_t ioapic_read(ioapic_t *apic, uint32_t reg) {
    mmio_write32(apic->regs, 0, reg);
    return mmio_read32(apic->regs, 0x10);
}

static void ioapic_write(ioapic_t *apic, uint32_t reg, uint32_t value) {
    mmio_write32(apic->regs, 0, reg);
    mmio_write32(apic->regs, 0x10, value);
}

static uint32_t apic_value(ioapic_pin_t *pin) {
    uint32_t flags = pin->irq.vector;

    if (pin->active_low) flags |= IOAPIC_ACTIVE_LOW;
    if (pin->level_triggered) flags |= IOAPIC_LEVEL_TRIGGERED;

    return flags;
}

static void free_pin(ioapic_t *apic, ioapic_pin_t *pin) {
    ioapic_write(apic, IOREDTBL(pin - apic->pins), IOAPIC_MASKED | X86_64_IDT_LAPIC_SPURIOUS);
    arch_irq_free(&pin->irq);
}

static ioapic_t *gsi_to_apic(uint32_t *irq) {
    uint32_t gsi = *irq;

    SLIST_FOREACH(ioapics, ioapic_t, node, apic) {
        if (apic->gsi_base <= gsi) {
            uint32_t offset = gsi - apic->gsi_base;

            if (offset < apic->num_pins) {
                *irq = offset;
                return apic;
            }
        }
    }

    return NULL;
}

static void x86_64_ioapic_init(void) {
    uacpi_table table;
    uacpi_status status = uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &table);
    if (uacpi_unlikely_error(status)) panic("ioapic: failed to find madt table: %s", uacpi_status_to_string(status));

    struct acpi_madt *madt = (struct acpi_madt *)table.ptr;

    if (madt->flags & ACPI_PCAT_COMPAT) {
        // disable pic by ensuring its spurious vector is correct and masking all irqs
        pio_write8(0x20, 0x11);
        pio_write8(0xa0, 0x11);
        pio_write8(0x21, X86_64_IDT_LAPIC_SPURIOUS - 7);
        pio_write8(0xa1, X86_64_IDT_LAPIC_SPURIOUS - 7);
        pio_write8(0x21, 4);
        pio_write8(0xa1, 2);
        pio_write8(0x21, 1);
        pio_write8(0xa1, 1);
        pio_write8(0x21, 0xff);
        pio_write8(0xa1, 0xff);
        have_8259 = true;
    }

    struct acpi_entry_hdr *cur = madt->entries;
    struct acpi_entry_hdr *end = (void *)madt + madt->hdr.length;

    for (int i = 0; i < 16; i++) {
        isa_irq_overrides[i].gsi = i;
    }

    while (cur < end) {
        if (cur->type == ACPI_MADT_ENTRY_TYPE_IOAPIC) {
            struct acpi_madt_ioapic *entry = (void *)cur;

            ioapic_t *ioapic = vmalloc(sizeof(*ioapic));
            if (unlikely(!ioapic)) panic("ioapic: failed to allocate ioapic info");
            memset(ioapic, 0, sizeof(*ioapic));

            int error = map_mmio(&ioapic->regs, entry->address, 0x14, PMAP_READABLE | PMAP_WRITABLE | PMAP_CACHE_UC);
            if (unlikely(error)) panic("ioapic: failed to map registers (%e)", error);

            ioapic->gsi_base = entry->gsi_base;
            ioapic->num_pins = ((ioapic_read(ioapic, IOAPICVER) >> 16) & 0xff) + 1;

            ioapic->pins = vmalloc(sizeof(*ioapic->pins) * ioapic->num_pins);
            if (unlikely(!ioapic->pins)) panic("ioapic: failed to allocate pin list");
            memset(ioapic->pins, 0, sizeof(*ioapic->pins) * ioapic->num_pins);

            for (uint32_t i = 0; i < ioapic->num_pins; i++) {
                ioapic_write(ioapic, IOREDTBL(i), IOAPIC_MASKED | X86_64_IDT_LAPIC_SPURIOUS);
                ioapic_write(ioapic, IOREDTBL(i) + 1, boot_cpu.arch.apic_id << 24);
            }

            slist_insert_tail(&ioapics, &ioapic->node);
        } else if (cur->type == ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE) {
            struct acpi_madt_interrupt_source_override *iso = (void *)cur;

            switch (iso->bus) {
            case 0:
                if (iso->source < 16) {
                    isa_irq_overrides[iso->source].gsi = iso->gsi;

                    if ((iso->flags & ACPI_MADT_POLARITY_MASK) == ACPI_MADT_POLARITY_ACTIVE_LOW) {
                        isa_irq_overrides[iso->source].flags |= IRQ_ACTIVE_LOW;
                    }

                    if ((iso->flags & ACPI_MADT_TRIGGERING_MASK) == ACPI_MADT_TRIGGERING_LEVEL) {
                        isa_irq_overrides[iso->source].flags |= IRQ_LEVEL_TRIGGERED;
                    }

                    uint32_t irq = iso->gsi;
                    ioapic_t *apic = gsi_to_apic(&irq);

                    if (likely(apic)) {
                        apic->pins[irq].has_isa_irq = true;
                    } else {
                        printk("ioapic: firmware requested interrupt override to nonexistent gsi %u\n", iso->gsi);
                    }
                } else {
                    printk("ioapic: invalid isa interrupt %u\n", iso->source);
                }
                break;
            default: printk("ioapic: firmware requested interrupt override on unknown bus %u\n", iso->bus); break;
            }
        }

        cur = (void *)cur + cur->length;
    }

    cur = madt->entries;

    while (cur < end) {
        if (cur->type == ACPI_MADT_ENTRY_TYPE_NMI_SOURCE) {
            struct acpi_madt_nmi_source *entry = (struct acpi_madt_nmi_source *)cur;

            uint32_t irq = entry->gsi;
            ioapic_t *apic = gsi_to_apic(&irq);

            if (apic) {
                ioapic_pin_t *pin = &apic->pins[irq];

                if (pin->count != 0) {
                    printk("ioapic: firmware requested duplicate nmi source on gsi %u\n", irq);
                } else if (pin->has_isa_irq) {
                    printk("ioapic: firmware requested nmi source on isa irq gsi %u\n", irq);
                } else {
                    pin->count = 1;
                    pin->masks = 0;
                    pin->active_low = (entry->flags & ACPI_MADT_POLARITY_MASK) == ACPI_MADT_POLARITY_ACTIVE_LOW;
                    pin->level_triggered = (entry->flags & ACPI_MADT_TRIGGERING_MASK) == ACPI_MADT_TRIGGERING_LEVEL;
                    pin->shareable = false;

                    if (pin->level_triggered) {
                        printk("ioapic: firmware requested level-triggered nmi, but nmis are always edge triggered\n");
                    }

                    ioapic_write(apic, IOREDTBL(irq), apic_value(pin) | IOAPIC_NMI);
                }
            } else {
                printk("ioapic: firmware requested nmi source on nonexistent gsi %u\n", irq);
            }
        }

        cur = (void *)cur + cur->length;
    }

    uacpi_table_unref(&table);
}

INIT_DEFINE_EARLY(
    x86_64_ioapic,
    x86_64_ioapic_init,
    INIT_REFERENCE(memory),
    INIT_REFERENCE(acpi_tables),
    INIT_REFERENCE(x86_64_lapic)
);

typedef struct {
    hlist_node_t node;
    struct ioapic *apic;
    uint32_t pin;
    bool masked;
    irq_func_t func;
    void *ctx;
} gsi_handler_t;

static void ioapic_handle_irq(void *ptr) {
    ioapic_pin_t *pin = ptr;
    spin_acq_noirq(&pin->lock);

    LIST_FOREACH(pin->handlers, gsi_handler_t, node, handler) {
        handler->func(handler->ctx);
    }

    spin_rel_noirq(&pin->lock);
}

static hydrogen_ret_t do_open_gsi(uint32_t gsi, int flags, irq_func_t func, void *ctx, bool isa) {
    ioapic_t *apic = gsi_to_apic(&gsi);
    if (unlikely(!apic)) return ret_error(ENOENT);

    gsi_handler_t *handler = vmalloc(sizeof(*handler));
    if (unlikely(!handler)) return ret_error(ENOMEM);
    memset(handler, 0, sizeof(*handler));

    handler->apic = apic;
    handler->pin = gsi;
    handler->func = func;
    handler->ctx = ctx;
    handler->masked = true;

    ioapic_pin_t *pin = &apic->pins[gsi];
    irq_state_t state = spin_acq(&pin->lock);
    spin_acq_noirq(&apic->lock);

    if (pin->count != 0) {
        if (!pin->shareable || (flags & IRQ_SHAREABLE) == 0 || !!(flags & IRQ_ACTIVE_LOW) != !!pin->active_low ||
            !!(flags & IRQ_LEVEL_TRIGGERED) != !!pin->level_triggered) {
            spin_rel_noirq(&apic->lock);
            spin_rel(&pin->lock, state);
            vfree(handler, sizeof(*handler));
            return ret_error(EBUSY);
        }

        pin->count += 1;
        if (pin->masks++) ioapic_write(apic, IOREDTBL(gsi), apic_value(pin) | IOAPIC_MASKED);
    } else if (pin->has_isa_irq && !isa) {
        spin_rel_noirq(&apic->lock);
        spin_rel(&pin->lock, state);
        vfree(handler, sizeof(*handler));
        return ret_error(EBUSY);
    } else {
        int error = arch_irq_allocate(&pin->irq, ioapic_handle_irq, pin);
        if (unlikely(error)) {
            spin_rel_noirq(&apic->lock);
            spin_rel(&pin->lock, state);
            vfree(handler, sizeof(*handler));
            return ret_error(error);
        }

        pin->count = 1;
        pin->masks = 1;
        pin->active_low = flags & IRQ_ACTIVE_LOW;
        pin->level_triggered = flags & IRQ_LEVEL_TRIGGERED;
        pin->shareable = flags & IRQ_SHAREABLE;
        ioapic_write(apic, IOREDTBL(gsi), apic_value(pin) | IOAPIC_MASKED);
    }

    hlist_insert_head(&pin->handlers, &handler->node);

    spin_rel_noirq(&apic->lock);
    spin_rel(&pin->lock, state);
    return ret_pointer(handler);
}

static hydrogen_ret_t gsi_open(irq_controller_t *self, uint32_t gsi, int flags, irq_func_t func, void *ctx) {
    return do_open_gsi(gsi, flags, func, ctx, false);
}

static void gsi_mask(irq_controller_t *self, void *ptr) {
    gsi_handler_t *handler = ptr;
    ioapic_t *apic = handler->apic;
    ioapic_pin_t *pin = &apic->pins[handler->pin];
    irq_state_t state = spin_acq(&apic->lock);

    if (!handler->masked) {
        if (pin->masks++ == 0) {
            ioapic_write(apic, IOREDTBL(handler->pin), apic_value(pin) | IOAPIC_MASKED);
        }

        handler->masked = true;
    }

    spin_rel(&apic->lock, state);
}

static void gsi_unmask(irq_controller_t *self, void *ptr) {
    gsi_handler_t *handler = ptr;
    ioapic_t *apic = handler->apic;
    ioapic_pin_t *pin = &apic->pins[handler->pin];
    irq_state_t state = spin_acq(&apic->lock);

    if (handler->masked) {
        if (--pin->masks == 0) {
            ioapic_write(apic, IOREDTBL(handler->pin), apic_value(pin));
        }

        handler->masked = false;
    }

    spin_rel(&apic->lock, state);
}

static void gsi_close(irq_controller_t *self, void *ptr) {
    gsi_handler_t *handler = ptr;
    ioapic_t *apic = handler->apic;
    ioapic_pin_t *pin = &apic->pins[handler->pin];
    irq_state_t state = spin_acq(&pin->lock);
    spin_acq_noirq(&apic->lock);

    hlist_remove(&pin->handlers, &handler->node);

    if (--pin->count == 0) {
        free_pin(apic, pin);
    } else if (handler->masked && --pin->masks == 0) {
        ioapic_write(apic, IOREDTBL(handler->pin), apic_value(pin));
    }

    spin_rel_noirq(&apic->lock);
    spin_rel(&pin->lock, state);
}

static const irq_controller_ops_t gsi_ops = {
    .open = gsi_open,
    .mask = gsi_mask,
    .unmask = gsi_unmask,
    .close = gsi_close,
};
irq_controller_t x86_64_gsi_controller = {.ops = &gsi_ops, .path = "/dev/acpi/gsi"};

static hydrogen_ret_t isa_irq_open(irq_controller_t *self, uint32_t irq, int flags, irq_func_t func, void *ctx) {
    if (unlikely(irq >= 16)) return ret_error(ENOENT);
    return do_open_gsi(isa_irq_overrides[irq].gsi, isa_irq_overrides[irq].flags, func, ctx, true);
}

static const irq_controller_ops_t isa_ops = {
    .open = isa_irq_open,
    .mask = gsi_mask,
    .unmask = gsi_unmask,
    .close = gsi_close,
};
irq_controller_t x86_64_isa_controller = {.ops = &isa_ops, .path = "/dev/i8259"};

static void init_ioapic_controllers(void) {
    int error = irq_controller_init(&x86_64_gsi_controller);
    if (unlikely(error)) panic("ioapic: failed to initialize gsi controller (%e)", error);

    if (have_8259) {
        error = irq_controller_init(&x86_64_isa_controller);
        if (unlikely(error)) panic("ioapic: failed to initialize isa controller (%e)", error);
    }
}

INIT_DEFINE(init_ioapic_controllers, init_ioapic_controllers, INIT_REFERENCE(create_acpi_devices));
