#include "drv/acpi.h"
#include "hydrogen/error.h"
#include "hydrogen/memory.h"
#include "kernel/compiler.h"
#include "limine.h"
#include "mem/kvmm.h"
#include "mem/vmalloc.h"
#include "sections.h"
#include "string.h"
#include "util/endian.h"
#include "util/logging.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint8_t signature[8];
    uint8_t checksum;
    uint8_t oem_id[6];
    uint8_t revision;
    uint32_t rsdt_address;
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t ext_checksum;
} __attribute__((packed)) rsdp_t;

typedef struct {
    acpi_header_t header;
    union {
        uint32_t entries32[0];
        uint64_t entries64[0];
    };
} __attribute__((packed)) root_table_t;

static const acpi_header_t **tables;
static size_t num_tables;

static bool acpi_checksum(const void *ptr, size_t size) {
    uint8_t sum = 0;
    const uint8_t *data = ptr;

    while (size--) {
        sum += *data++;
    }

    return sum == 0;
}

static const rsdp_t *map_rsdp(size_t *len_out) {
    static LIMINE_REQ struct limine_rsdp_request rsdp_req = {.id = LIMINE_RSDP_REQUEST};
    if (!rsdp_req.response) return NULL;
    uint64_t addr = rsdp_req.response->address;

    void *ptr;
    hydrogen_error_t error = map_phys_mem(&ptr, addr, 24, HYDROGEN_MEM_READ);
    if (unlikely(error)) {
        printk("acpi: failed to map rsdp header at 0x%X (%d)\n", rsdp_req.response->address, error);
        return NULL;
    }

    const rsdp_t *rsdp = ptr;
    if (unlikely(memcmp(rsdp, "RSD PTR ", 8))) {
        printk("acpi: rsdp signature invalid\n");
        unmap_phys_mem(ptr, 24);
        return NULL;
    }

    if (unlikely(!acpi_checksum(rsdp, 20))) {
        printk("acpi: rsdp checksum invalid\n");
        unmap_phys_mem(ptr, 24);
        return NULL;
    }

    size_t real_len;

    if (rsdp->revision >= 2) {
        size_t length = le32(rsdp->length);
        unmap_phys_mem(ptr, length);

        error = map_phys_mem(&ptr, addr, length, HYDROGEN_MEM_READ);
        if (unlikely(error)) {
            printk("acpi: failed to map rsdp at 0x%X-0x%X (%d)\n", addr, addr + length, error);
            return NULL;
        }

        if (unlikely(!acpi_checksum(ptr, length))) {
            printk("acpi: rsdp extended checksum invalid\n");
            unmap_phys_mem(ptr, length);
            return NULL;
        }

        rsdp = ptr;
        real_len = length;
        *len_out = length;
    } else {
        real_len = 20;
        *len_out = 24;
    }

    printk("acpi: %S v%2x @ 0x%X-0x%X (%S)\n",
           rsdp->signature,
           sizeof(rsdp->signature),
           rsdp->revision,
           addr,
           addr + real_len,
           rsdp->oem_id,
           sizeof(rsdp->oem_id));
    return rsdp;
}

void init_acpi(void) {
    size_t rsdp_len;
    const rsdp_t *rsdp = map_rsdp(&rsdp_len);
    if (unlikely(!rsdp)) return;

    bool xsdt = rsdp->revision >= 2;
    uint64_t addr = xsdt ? le64(rsdp->xsdt_address) : le32(rsdp->rsdt_address);
    unmap_phys_mem(rsdp, rsdp_len);

    const acpi_header_t *header;
    hydrogen_error_t error = map_acpi_table(&header, addr);
    if (unlikely(error)) {
        printk("acpi: failed to map root table (%d)\n", error);
        return;
    }
    const root_table_t *root_table = (const root_table_t *)header;

    num_tables = (le32(root_table->header.length) - sizeof(root_table->header)) / (xsdt ? 8 : 4);
    tables = vmalloc(num_tables * sizeof(*tables));
    if (unlikely(!tables)) {
        printk("acpi: failed to allocate table array\n");
        unmap_phys_mem(header, le32(header->length));
        return;
    }

    for (size_t i = 0; i < num_tables; i++) {
        uint64_t addr = xsdt ? le64(root_table->entries64[i]) : le32(root_table->entries32[i]);
        hydrogen_error_t error = map_acpi_table(&tables[i], addr);

        if (unlikely(error)) {
            printk("acpi: failed to map table (%d)\n", error);
            tables[i] = NULL;
        }
    }

    unmap_phys_mem(header, le32(header->length));
}

hydrogen_error_t map_acpi_table(const acpi_header_t **out, uint64_t addr) {
    void *ptr;
    hydrogen_error_t error = map_phys_mem(&ptr, addr, sizeof(acpi_header_t), HYDROGEN_MEM_READ);
    if (unlikely(error)) return error;
    size_t length = le32(((const acpi_header_t *)ptr)->length);
    unmap_phys_mem(ptr, sizeof(acpi_header_t));

    error = map_phys_mem(&ptr, addr, length, HYDROGEN_MEM_READ);
    if (unlikely(error)) return error;
    const acpi_header_t *header = ptr;

    if (unlikely(!acpi_checksum(header, length))) {
        unmap_phys_mem(ptr, length);
        return HYDROGEN_INVALID_FORMAT;
    }

    printk("acpi: %S v%2x @ 0x%X-0x%X (%S %S 0x%8x %S 0x%8x)\n",
           header->signature,
           sizeof(header->signature),
           header->revision,
           addr,
           addr + length,
           header->oem_id,
           sizeof(header->oem_id),
           header->oem_table_id,
           sizeof(header->oem_table_id),
           le32(header->oem_revision),
           header->creator_id,
           sizeof(header->creator_id),
           le32(header->creator_revision));
    *out = header;
    return HYDROGEN_SUCCESS;
}

const acpi_header_t *get_acpi_table(const char signature[4]) {
    for (size_t i = 0; i < num_tables; i++) {
        const acpi_header_t *table = tables[i];
        if (likely(table) && memcmp(table->signature, signature, 4) == 0) return table;
    }

    return NULL;
}
