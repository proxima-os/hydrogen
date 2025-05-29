#include "drv/pci/config-access.h"
#include "arch/pmap.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "mem/kvmm.h"
#include "mem/vmalloc.h"
#include "uacpi/acpi.h"
#include "uacpi/status.h"
#include "uacpi/tables.h"
#include "util/printk.h"
#include <stdint.h>

typedef struct {
    uint16_t segment;
    uint8_t bus_head;
    uint8_t bus_tail;
    uintptr_t virt;
} ecam_range_t;

static ecam_range_t *ranges;
static size_t num_ranges;

static void init_config_access(void) {
    uacpi_table table;
    uacpi_status status = uacpi_table_find_by_signature(ACPI_MCFG_SIGNATURE, &table);
    if (uacpi_unlikely_error(status)) {
        printk("pci: failed to find mcfg table: %s\n", uacpi_status_to_string(status));
        return;
    }

    struct acpi_mcfg *mcfg = table.ptr;
    struct acpi_mcfg_allocation *entries = mcfg->entries;
    struct acpi_mcfg_allocation *mcfg_end = (void *)mcfg + mcfg->hdr.length;

    num_ranges = mcfg_end - entries;
    ranges = vmalloc(sizeof(*ranges) * num_ranges);
    if (unlikely(!ranges)) {
        printk("pci: failed to allocate range array\n");
        uacpi_table_unref(&table);
        return;
    }

    for (size_t i = 0; i < num_ranges; i++) {
        ecam_range_t *range = &ranges[i];
        range->segment = entries[i].segment;
        range->bus_head = entries[i].start_bus;
        range->bus_tail = entries[i].end_bus;

        int error = map_mmio(
            &range->virt,
            range->segment + ((uint64_t)range->bus_head << 20),
            (uint64_t)(range->bus_tail - range->bus_head + 1) << 20,
            PMAP_READABLE | PMAP_WRITABLE | PMAP_CACHE_UC
        );

        if (unlikely(error)) {
            printk("pci: failed to map ecam range (%e)\n", error);
            uacpi_table_unref(&table);
            vfree(ranges, sizeof(*ranges) * num_ranges);
            num_ranges = 0;
        }
    }

    uacpi_table_unref(&table);
}

INIT_DEFINE(pci_config_access, init_config_access);

bool pci_config_get(const pci_address_t *address, pci_config_t *out) {
    for (size_t i = 0; i < num_ranges; i++) {
        ecam_range_t *range = &ranges[i];

        if (range->segment == address->segment && range->bus_head <= address->bus && address->bus <= range->bus_tail) {
            uintptr_t offset = ((uint64_t)(address->bus - range->bus_head) << 20) | ((uint64_t)address->device << 15) |
                               ((uint64_t)address->function << 12);
            *out = (pci_config_t){range->virt + offset};
            return true;
        }
    }

    return false;
}
