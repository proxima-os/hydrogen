/*#pragma once

#include "util/list.h"
#include <hydrogen/types.h>
#include <stdbool.h>
#include <stdint.h>

#define GSI_ACTIVE_LOW (1 << 0)
#define GSI_LEVEL_TRIGGERED (1 << 1)
#define GSI_SHAREABLE (1 << 2)

typedef struct {
    list_node_t node;
    struct ioapic *apic;
    uint32_t pin;
    bool (*func)(void *);
    void *ctx;
    bool masked;
} gsi_handler_t;

hydrogen_ret_t gsi_install(uint32_t gsi, int flags, bool (*func)(void *), void *ctx);
void gsi_mask(gsi_handler_t *handler);
void gsi_unmask(gsi_handler_t *handler);
void gsi_uninstall(gsi_handler_t *handler);
*/
