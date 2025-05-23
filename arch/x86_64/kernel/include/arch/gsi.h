#pragma once

#include "arch/irq.h"
#include <stdbool.h>
#include <stdint.h>

#define GSI_ACTIVE_HIGH 0
#define GSI_ACTIVE_LOW (1 << 0)
#define GSI_EDGE_TRIGGERED 0
#define GSI_LEVEL_TRIGGERED (1 << 1)

typedef struct {
    struct ioapic *ioapic;
    uint32_t index;
    irq_handler_t handler;
} gsi_handler_t;

int gsi_install(gsi_handler_t *out, uint32_t gsi, bool (*handler)(void *), void *ctx, int flags);
void gsi_uninstall(gsi_handler_t *handler);
