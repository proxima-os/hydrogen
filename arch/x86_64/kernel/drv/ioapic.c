#include "x86_64/ioapic.h"
#include "acpi/acpi.h" /* IWYU pragma: keep */
#include "arch/mmio.h"
#include "arch/pio.h"
#include "arch/pmap.h"
#include "cpu/cpudata.h"
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
    slist_node_t node;
    uintptr_t regs;
    uint32_t gsi_base;
    uint32_t num_irqs;
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

            for (uint32_t i = 0; i < ioapic->num_irqs; i++) {
                ioapic_write(ioapic, IOREDTBL(i), IOAPIC_MASKED | X86_64_IDT_LAPIC_SPURIOUS);
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
                uint32_t desc = IOAPIC_NMI;

                if ((entry->flags & ACPI_MADT_POLARITY_MASK) == ACPI_MADT_POLARITY_ACTIVE_LOW) {
                    desc |= IOAPIC_ACTIVE_LOW;
                }

                if ((entry->flags & ACPI_MADT_TRIGGERING_MASK) == ACPI_MADT_TRIGGERING_LEVEL) {
                    printk("ioapic: firmware requested level-triggered nmi, but nmis are always edge triggered\n");
                }

                ioapic_write(apic, IOREDTBL(irq) + 1, boot_cpu.arch.apic_id << 24);
                ioapic_write(apic, IOREDTBL(irq), desc);
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
