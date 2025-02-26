#include "drv/pic.h"
#include "asm/mmio.h"
#include "asm/pio.h"
#include "drv/acpi.h"
#include "hydrogen/error.h"
#include "hydrogen/memory.h"
#include "kernel/compiler.h"
#include "mem/kvmm.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "util/panic.h"
#include <stdint.h>

#define IOAPICVER 1
#define IOREDTBL(x) (0x10 + (x) * 2)

#define IOAPIC_NMI 0x400
#define IOAPIC_ACTIVE_LOW 0x2000
#define IOAPIC_LEVEL 0x8000
#define IOAPIC_MASKED 0x10000

struct ioapic {
    struct ioapic *next;
    void *regs;
    uint32_t gsi_base;
    uint32_t num_irqs;
};

cpu_t *pic_cpus;

static struct ioapic *ioapics;

static uint32_t ioapic_read(struct ioapic *apic, unsigned reg) {
    mmio_write32(apic->regs, 0, reg);
    return mmio_read32(apic->regs, 0x10);
}

static void ioapic_write(struct ioapic *apic, unsigned reg, uint32_t value) {
    mmio_write32(apic->regs, 0, reg);
    mmio_write32(apic->regs, 0x10, value);
}

static struct ioapic *get_pic_for_gsi(uint32_t gsi) {
    for (struct ioapic *pic = ioapics; pic != NULL; pic = pic->next) {
        if (gsi >= pic->gsi_base && gsi - pic->gsi_base < pic->num_irqs) {
            return pic;
        }
    }

    return NULL;
}

void init_pic(void) {
    const acpi_madt_t *madt = (const acpi_madt_t *)get_acpi_table("APIC");
    if (unlikely(!madt)) panic("madt table not found");

    if (madt->flags & ACPI_MADT_PCAT_COMPAT) {
        outb(0x20, 0x11);
        outb(0xa0, 0x11);
        outb(0x21, 0xf8);
        outb(0xa1, 0xf8);
        outb(0x21, 4);
        outb(0xa1, 2);
        outb(0x21, 1);
        outb(0xa1, 1);
        outb(0x21, 0xff);
        outb(0xa1, 0xff);
    }

    ACPI_MADT_FOREACH(madt, entry) {
        if (entry->type == ACPI_MADT_IOAPIC) {
            struct ioapic *apic = vmalloc(sizeof(*apic));
            if (unlikely(!apic)) panic("failed to allocate i/o apic info");
            memset(apic, 0, sizeof(*apic));

            apic->next = ioapics;
            apic->gsi_base = entry->ioapic.gsi_base;

            hydrogen_error_t error = map_phys_mem(
                    &apic->regs,
                    entry->ioapic.address,
                    0x14,
                    HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE | HYDROGEN_MEM_NO_CACHE
            );
            if (unlikely(error)) panic("failed to map i/o apic registers");

            apic->num_irqs = ((ioapic_read(apic, IOAPICVER) >> 16) & 0xff) + 1;

            for (unsigned i = 0; i < apic->num_irqs; i++) {
                ioapic_write(apic, IOREDTBL(i), IOAPIC_MASKED);
            }
        }
    }

    ACPI_MADT_FOREACH(madt, entry) {
        if (entry->type == ACPI_MADT_NMI) {
            struct ioapic *pic = get_pic_for_gsi(entry->nmi.gsi);
            if (unlikely(!pic)) panic("no i/o apic for gsi in nmi entry");

            // TODO: Pick CPU properly
            uint64_t value = IOAPIC_NMI | ((uint64_t)pic_cpus->apic_id << 56);

            if ((entry->nmi.flags & ACPI_MADT_ISO_POLARITY_MASK) == ACPI_MADT_ISO_ACTIVE_LOW) {
                value |= IOAPIC_ACTIVE_LOW;
            }

            if ((entry->nmi.flags & ACPI_MADT_ISO_TRIGGER_MASK) == ACPI_MADT_ISO_TRIGGER_LEVEL) {
                value |= IOAPIC_LEVEL;
            }

            uint32_t irq = entry->nmi.gsi - pic->gsi_base;
            ioapic_write(pic, IOREDTBL(irq) + 1, value >> 32);
            ioapic_write(pic, IOREDTBL(irq), value);
        }
    }
}
