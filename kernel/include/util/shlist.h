#pragma once

#include "kernel/compiler.h"
#include <stdbool.h>

typedef struct shlist_node {
    struct shlist_node *next;
} shlist_node_t;

typedef struct {
    shlist_node_t *head;
} shlist_t;

#define SHLIST_HEAD(list, type, name) CONTAINER(type, name, (list).head)
#define SHLIST_NEXT(node, type, name) CONTAINER(type, name, (node).name.next)

#define SHLIST_FOREACH(list, type, name, var) \
    for (type *var = SHLIST_HEAD(list, type, name); var != NULL; var = SHLIST_NEXT(*var, type, name))

static inline bool shlist_empty(shlist_t *list) {
    return list->head == NULL;
}

static inline void shlist_clear(shlist_t *list) {
    list->head = NULL;
}

static inline void shlist_remove(shlist_t *list, shlist_node_t *node, shlist_node_t *prev) {
    if (prev != NULL) {
        ASSERT(prev->next == node);
        prev->next = node->next;
    } else {
        ASSERT(list->head == node);
        list->head = node->next;
    }
}

static inline shlist_node_t *shlist_remove_head(shlist_t *list) {
    shlist_node_t *node = list->head;

    if (node != NULL) {
        list->head = node->next;
    }

    return node;
}

#define SHLIST_REMOVE_HEAD(list, type, name) CONTAINER(type, name, shlist_remove_head(&(list)))

static inline void shlist_insert_head(shlist_t *list, shlist_node_t *node) {
    node->next = list->head;
    list->head = node;
}

static inline void shlist_insert_after(shlist_t *list, shlist_node_t *anchor, shlist_node_t *node) {
    if (anchor != NULL) {
        node->next = anchor->next;
        anchor->next = node;
    } else {
        node->next = list->head;
        list->head = node;
    }
}
