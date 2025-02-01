#pragma once

#include "hydrogen/error.h"
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
} __attribute__((packed, aligned(4))) acpi_header_t;

typedef struct {
    uint8_t address_space;
    uint8_t bit_width;
    uint8_t bit_offset;
    uint8_t reserved;
    uint64_t address;
} __attribute__((packed, aligned(4))) acpi_gas_t;

typedef struct {
    acpi_header_t header;
    uint32_t hardware_id;
    acpi_gas_t base;
    uint8_t seq_num;
    uint16_t min_period;
    uint8_t oem_protection;
} __attribute__((packed, aligned(4))) acpi_hpet_t;

void init_acpi(void);

hydrogen_error_t map_acpi_table(const acpi_header_t **out, uint64_t addr);

const acpi_header_t *get_acpi_table(const char signature[4]);
