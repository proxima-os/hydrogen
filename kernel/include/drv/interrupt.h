#pragma once

#include "util/eventqueue.h"
#include "util/list.h"
#include "util/object.h"
#include "util/spinlock.h"
#include <hydrogen/types.h>
#include <stdint.h>

typedef struct interrupt interrupt_t;

typedef struct {
    object_ops_t base;
    void (*mask)(interrupt_t *self);
    void (*unmask)(interrupt_t *self);
} interrupt_ops_t;

struct interrupt {
    object_t base;
    spinlock_t lock;
    bool pending;
    size_t id;
    list_t waiting;
    event_source_t pending_source;
};

void interrupt_init(interrupt_t *irq, const interrupt_ops_t *ops);
void interrupt_trigger(interrupt_t *irq);

hydrogen_ret_t interrupt_wait(interrupt_t *irq, uint64_t deadline, uint32_t flags);
int interrupt_claim(interrupt_t *irq, size_t id);

void interrupt_free(interrupt_t *irq);
int interrupt_event_add(object_t *irq, uint32_t rights, active_event_t *event);
void interrupt_event_del(object_t *irq, active_event_t *event);
