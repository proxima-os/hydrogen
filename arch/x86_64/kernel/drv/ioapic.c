#include "x86_64/ioapic.h"
#include "arch/gsi.h"
#include "arch/irq.h"
#include "arch/mmio.h"
#include "arch/pio.h"
#include "arch/pmap.h"
#include "cpu/cpudata.h"
#include "drv/acpi/acpi.h" /* IWYU pragma: keep */
#include "errno.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "mem/kvmm.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "uacpi/acpi.h"
#include "uacpi/status.h"
#include "uacpi/tables.h"
#include "util/panic.h"
#include "util/printk.h"
#include "util/slist.h"
#include "util/spinlock.h"
#include "x86_64/idtvec.h"
#include "x86_64/lapic.h"
#include <stdint.h>

#define IOAPICID 0
#define IOAPICVER 1
#define IOREDTBL(i) (0x10 + (i) * 2)

#define IOAPIC_NMI (4u << 8)
#define IOAPIC_ACTIVE_LOW (1u << 13)
#define IOAPIC_LEVEL_TRIGGERED (1u << 15)
#define IOAPIC_MASKED (1u << 16)

typedef struct {
    irq_t irq;
    size_t count;
    bool active_low : 1;
    bool level_triggered : 1;
    bool shareable : 1;
} ioapic_pin_t;

typedef struct ioapic {
    slist_node_t node;
    uintptr_t regs;
    uint32_t gsi_base;
    uint32_t num_irqs;
    spinlock_t lock;
    ioapic_pin_t *pins;
} ioapic_t;

static struct {
    uint32_t gsi;
    uint16_t flags;
} isa_irq_overrides[16];

_Static_assert(((X86_64_IDT_LAPIC_SPURIOUS - 7) & 7) == 0, "Spurious IRQ must have the 3 lowest bits set");

static slist_t ioapics;

static uint32_t ioapic_read(ioapic_t *apic, uint32_t reg) {
    mmio_write32(apic->regs, 0, reg);
    return mmio_read32(apic->regs, 0x10);
}

static void ioapic_write(ioapic_t *apic, uint32_t reg, uint32_t value) {
    mmio_write32(apic->regs, 0, reg);
    mmio_write32(apic->regs, 0x10, value);
}

static ioapic_t *gsi_to_apic(uint32_t *irq) {
    uint32_t gsi = *irq;

    SLIST_FOREACH(ioapics, ioapic_t, node, apic) {
        if (apic->gsi_base <= gsi) {
            uint32_t offset = gsi - apic->gsi_base;

            if (offset < apic->num_irqs) {
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
    }

    struct acpi_entry_hdr *cur = madt->entries;
    struct acpi_entry_hdr *end = (void *)madt + madt->hdr.length;

    while (cur < end) {
        if (cur->type == ACPI_MADT_ENTRY_TYPE_IOAPIC) {
            struct acpi_madt_ioapic *entry = (void *)cur;

            ioapic_t *ioapic = vmalloc(sizeof(*ioapic));
            if (unlikely(!ioapic)) panic("ioapic: failed to allocate ioapic info");
            memset(ioapic, 0, sizeof(*ioapic));

            int error = map_mmio(&ioapic->regs, entry->address, 0x14, PMAP_READABLE | PMAP_WRITABLE | PMAP_CACHE_UC);
            if (unlikely(error)) panic("ioapic: failed to map registers (%e)", error);

            ioapic->gsi_base = entry->gsi_base;
            ioapic->num_irqs = ((ioapic_read(ioapic, IOAPICVER) >> 16) & 0xff) + 1;

            ioapic->pins = vmalloc(sizeof(*ioapic->pins) * ioapic->num_irqs);
            if (unlikely(!ioapic->pins)) panic("ioapic: failed to allocate pin list");
            memset(ioapic->pins, 0, sizeof(*ioapic->pins) * ioapic->num_irqs);

            for (uint32_t i = 0; i < ioapic->num_irqs; i++) {
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
                    isa_irq_overrides[iso->flags].flags = iso->flags;
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
                } else {
                    pin->count = 1;
                    pin->active_low = (entry->flags & ACPI_MADT_POLARITY_MASK) == ACPI_MADT_POLARITY_ACTIVE_LOW;
                    pin->level_triggered = (entry->flags & ACPI_MADT_TRIGGERING_MASK) == ACPI_MADT_TRIGGERING_LEVEL;

                    if (pin->level_triggered) {
                        printk("ioapic: firmware requested level-triggered nmi, but nmis are always edge triggered\n");
                    }

                    uint32_t desc = IOAPIC_NMI;
                    if (pin->active_low) desc |= IOAPIC_ACTIVE_LOW;
                    if (pin->level_triggered) desc |= IOAPIC_LEVEL_TRIGGERED;
                    ioapic_write(apic, IOREDTBL(irq), desc);
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

int gsi_install(gsi_handler_t *out, uint32_t gsi, bool (*handler)(void *), void *ctx, int flags) {
    ioapic_t *ioapic = gsi_to_apic(&gsi);
    if (unlikely(!ioapic)) return ENOENT;

    irq_state_t state = spin_acq(&ioapic->lock);

    ioapic_pin_t *pin = &ioapic->pins[gsi];

    if (pin->count != 0) {
        if (!pin->shareable || pin->level_triggered != !!(flags & GSI_LEVEL_TRIGGERED) ||
            pin->active_low != !!(flags & GSI_ACTIVE_LOW)) {
            spin_rel(&ioapic->lock, state);
            return EBUSY;
        }
    } else {
        int error = arch_irq_allocate(&pin->irq);

        if (unlikely(error)) {
            spin_rel(&ioapic->lock, state);
            return error;
        }

        pin->active_low = flags & GSI_ACTIVE_LOW;
        pin->level_triggered = flags & GSI_LEVEL_TRIGGERED;
        pin->shareable = flags & GSI_SHAREABLE;

        uint32_t entry = pin->irq.vector;
        if (pin->active_low) entry |= IOAPIC_ACTIVE_LOW;
        if (pin->level_triggered) entry |= IOAPIC_LEVEL_TRIGGERED;
        ioapic_write(ioapic, IOREDTBL(gsi), entry);
    }

    out->handler.func = handler;
    out->handler.ctx = ctx;
    arch_irq_add_handler(&pin->irq, &out->handler);
    pin->count += 1;

    spin_rel(&ioapic->lock, state);

    out->ioapic = ioapic;
    out->index = gsi;
    return 0;
}

void gsi_uninstall(gsi_handler_t *handler) {
    irq_state_t state = spin_acq(&handler->ioapic->lock);
    ioapic_pin_t *pin = &handler->ioapic->pins[handler->index];

    arch_irq_remove_handler(&pin->irq, &handler->handler);

    if (--pin->count == 0) {
        ioapic_write(handler->ioapic, IOREDTBL(handler->index), IOAPIC_MASKED);
        arch_irq_free(&pin->irq);
    }

    spin_rel(&handler->ioapic->lock, state);
}
