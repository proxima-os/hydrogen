#pragma once

#include "fs/vfs.h"
#include "util/eventqueue.h"
#include "util/list.h"
#include "util/object.h"
#include "util/spinlock.h"
#include <hydrogen/types.h>
#include <stddef.h>
#include <stdint.h>

#define IRQ_SHAREABLE (1 << 0)
#define IRQ_ACTIVE_LOW (1 << 1)
#define IRQ_LEVEL_TRIGGERED (1 << 2)

typedef void (*irq_func_t)(void *);

typedef struct irq_controller irq_controller_t;

typedef struct {
    hydrogen_ret_t (*open)(irq_controller_t *self, uint32_t irq, int flags, irq_func_t func, void *ctx);
    void (*mask)(irq_controller_t *self, void *irq);
    void (*unmask)(irq_controller_t *self, void *irq);
    void (*close)(irq_controller_t *self, void *irq);
} irq_controller_ops_t;

struct irq_controller {
    fs_device_t base;
    const irq_controller_ops_t *ops;
    const char *path;
};

typedef struct {
    object_t base;
    irq_controller_t *controller;
    spinlock_t lock;
    size_t pending;
    list_t waiting;
    event_source_t pending_source;
    void *irq;
} interrupt_t;

int irq_controller_init(irq_controller_t *controller);

int interrupt_wait(interrupt_t *irq, uint64_t deadline, uint32_t flags);
int interrupt_complete(interrupt_t *irq);

/*void interrupt_init(interrupt_t *irq, const interrupt_ops_t *ops);
void interrupt_trigger(interrupt_t *irq);

void interrupt_free(interrupt_t *irq);
int interrupt_event_add(object_t *irq, uint32_t rights, active_event_t *event);
void interrupt_event_del(object_t *irq, active_event_t *event);*/
