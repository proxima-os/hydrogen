#pragma once

#include "util/endian.h"
#include <stdint.h>

typedef struct {
    uint8_t signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    uint8_t oem_id[6];
    uint8_t oem_table_id[8];
    uint32_t oem_revision;
    uint8_t creator_id[4];
    uint32_t creator_revision;
} __attribute__((packed)) acpi_header_t;

typedef struct {
    uint8_t address_space;
    uint8_t bit_width;
    uint8_t bit_offset;
    uint8_t reserved;
    uint64_t address;
} __attribute__((packed)) acpi_gas_t;

typedef struct {
    acpi_header_t header;
    uint32_t hardware_id;
    acpi_gas_t base;
    uint8_t seq_num;
    uint16_t min_period;
    uint8_t oem_protection;
} __attribute__((packed)) acpi_hpet_t;

typedef struct {
    acpi_header_t header;
    uint32_t lapic_addr;
    uint32_t flags;
} __attribute__((packed)) acpi_madt_t;

#define ACPI_MADT_PCAT_COMPAT 1

#define ACPI_MADT_XAPIC 0
#define ACPI_MADT_IOAPIC 1
#define ACPI_MADT_ISO 2
#define ACPI_MADT_NMI 3
#define ACPI_MADT_XAPIC_NMI 4
#define ACPI_MADT_X2APIC 9
#define ACPI_MADT_X2APIC_NMI 10

#define ACPI_MADT_LAPIC_ENABLED 1
#define ACPI_MADT_LAPIC_ONLINE_CAPABLE 2

#define ACPI_MADT_ISO_POLARITY_MASK 3
#define ACPI_MADT_ISO_ACTIVE_HIGH 1
#define ACPI_MADT_ISO_ACTIVE_LOW 3
#define ACPI_MADT_ISO_TRIGGER_MASK (3 << 2)
#define ACPI_MADT_ISO_TRIGGER_EDGE (1 << 2)
#define ACPI_MADT_ISO_TRIGGER_LEVEL (3 << 2)

typedef struct {
    uint8_t type;
    uint8_t length;
    union {
        struct {
            uint8_t acpi_id;
            uint8_t apic_id;
            uint32_t flags;
        } __attribute__((packed)) xapic;
        struct {
            uint8_t id;
            uint8_t reserved;
            uint32_t address;
            uint32_t gsi_base;
        } __attribute__((packed)) ioapic;
        struct {
            uint8_t bus;
            uint8_t source;
            uint32_t gsi;
            uint16_t flags;
        } __attribute__((packed)) iso;
        struct {
            uint16_t flags;
            uint32_t gsi;
        } __attribute__((packed)) nmi;
        struct {
            uint8_t acpi_id;
            uint16_t flags;
            uint8_t input;
        } __attribute__((packed)) xapic_nmi;
        struct {
            uint16_t reserved;
            uint32_t apic_id;
            uint32_t flags;
            uint32_t acpi_id;
        } __attribute__((packed)) x2apic;
        struct {
            uint16_t flags;
            uint32_t acpi_id;
            uint8_t input;
            uint8_t reserved[3];
        } __attribute__((packed)) x2apic_nmi;
    };
} __attribute__((packed)) acpi_madt_entry_t;

#define ACPI_MADT_FOREACH(madt, var)                                                                                   \
    for (const acpi_madt_entry_t *var = (const void *)((madt) + 1);                                                    \
         (const void *)var < (const void *)(madt) + le32((madt)->header.length);                                       \
         var = (const void *)var + var->length)

void init_acpi(void);

int map_acpi_table(const acpi_header_t **out, uint64_t addr);

const acpi_header_t *get_acpi_table(const char signature[4]);
