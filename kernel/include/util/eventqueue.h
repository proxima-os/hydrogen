#pragma once

#include "proc/mutex.h"
#include "util/hlist.h"
#include "util/list.h"
#include "util/object.h"
#include <hydrogen/eventqueue.h>
#include <hydrogen/types.h>
#include <stdint.h>

typedef struct {
    object_t base;
    mutex_t lock;
    hlist_t *table;
    size_t table_capacity;
    size_t table_count;
    list_t events;
    mutex_t pending_lock;
    list_t pending;
    list_t waiting;
    size_t num_waking; // The number of pending events that can wake up waiters.
} event_queue_t;

typedef struct {
    object_t *object;
    hydrogen_event_type_t type;
    uint32_t padding;
    uint64_t data;
} event_source_id_t;

typedef struct active_event {
    event_queue_t *queue;
    list_node_t node;
    hlist_node_t table_node;
    list_node_t pending_node;
    list_node_t source_node;
    event_source_id_t source;
    uint64_t hash;
    void *priv;
    void *ctx;
    uint32_t flags;
} active_event_t;

int event_queue_create(event_queue_t **out);
int event_queue_add(
    event_queue_t *queue,
    object_t *object,
    object_rights_t rights,
    hydrogen_event_type_t type,
    uint64_t data,
    void *ctx,
    uint32_t flags
);
hydrogen_ret_t event_queue_remove(event_queue_t *queue, object_t *object, hydrogen_event_type_t type, uint64_t data);
hydrogen_ret_t event_queue_wait(event_queue_t *queue, hydrogen_event_t *events, size_t count, uint64_t deadline);

typedef struct {
    mutex_t lock;
    list_t events;
    bool pending;
} event_source_t;

int event_source_add(event_source_t *source, active_event_t *event);
void event_source_del(event_source_t *source, active_event_t *event);

void event_source_cleanup(event_source_t *source);
void event_source_signal(event_source_t *source);
void event_source_reset(event_source_t *source);
