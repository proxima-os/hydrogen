#pragma once

#include "kernel/compiler.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct hlist_node {
    struct hlist_node *prev;
    struct hlist_node *next;
} hlist_node_t;

typedef struct {
    hlist_node_t *head;
} hlist_t;

#define HLIST_HEAD(list, type, name) CONTAINER(type, name, (list).head)
#define HLIST_PREV(node, type, name) CONTAINER(type, name, (node).name.prev)
#define HLIST_NEXT(node, type, name) CONTAINER(type, name, (node).name.next)

#define HLIST_FOREACH(list, type, name, var) \
    for (type *var = HLIST_HEAD(list, type, name); var != NULL; var = HLIST_NEXT(*var, type, name))

static inline bool hlist_empty(hlist_t *list) {
    return list->head == NULL;
}

static inline void hlist_clear(hlist_t *list) {
    list->head = NULL;
}

static inline void hlist_remove(hlist_t *list, hlist_node_t *node) {
    if (node->prev) node->prev->next = node->next;
    else list->head = node->next;

    if (node->next) node->next->prev = node->prev;
}

static inline hlist_node_t *hlist_remove_head(hlist_t *list) {
    hlist_node_t *node = list->head;

    if (node) {
        list->head = node->next;

        if (node->next) node->next->prev = NULL;
    }

    return node;
}

#define HLIST_REMOVE_HEAD(list, type, name) CONTAINER(type, name, hlist_remove_head(&(list)))

static inline void hlist_insert_head(hlist_t *list, hlist_node_t *node) {
    node->prev = NULL;
    node->next = list->head;

    if (node->next) node->next->prev = node;

    list->head = node;
}

static inline void hlist_insert_after(hlist_t *list, hlist_node_t *anchor, hlist_node_t *node) {
    node->prev = anchor;

    if (anchor) {
        node->next = anchor->next;
        anchor->next = node;
    } else {
        node->next = list->head;
        list->head = node;
    }

    if (node->next) node->next->prev = node;
}
