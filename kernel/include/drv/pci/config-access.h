#pragma once

#include "arch/mmio.h"
#include "init/task.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t segment;
    uint8_t bus;
    uint8_t device;
    uint8_t function;
} pci_address_t;

typedef struct {
    uintptr_t base;
} pci_config_t;

INIT_DECLARE(pci_config_access);

bool pci_config_get(const pci_address_t *address, pci_config_t *out);

static inline uint8_t pci_read8(pci_config_t config, size_t offset) {
    return mmio_read8(config.base, offset);
}

static inline uint16_t pci_read16(pci_config_t config, size_t offset) {
    return mmio_read16(config.base, offset);
}

static inline uint32_t pci_read32(pci_config_t config, size_t offset) {
    return mmio_read32(config.base, offset);
}

static inline void pci_write8(pci_config_t config, size_t offset, uint8_t value) {
    mmio_write8(config.base, offset, value);
}

static inline void pci_write16(pci_config_t config, size_t offset, uint16_t value) {
    mmio_write16(config.base, offset, value);
}

static inline void pci_write32(pci_config_t config, size_t offset, uint32_t value) {
    mmio_write32(config.base, offset, value);
}
