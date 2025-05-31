#pragma once

#include "kernel/compiler.h"
#include <stdbool.h>

typedef struct slist_node {
    struct slist_node *next;
} slist_node_t;

typedef struct {
    slist_node_t *head;
    slist_node_t *tail; // only valid if head != NULL
} slist_t;

#define SLIST_HEAD(list, type, name) CONTAINER(type, name, (list).head)
#define SLIST_TAIL(list, type, name)                           \
    ({                                                         \
        slist_t _list = (list);                                \
        _list.head ? CONTAINER(type, name, _list.tail) : NULL; \
    })
#define SLIST_NEXT(node, type, name) CONTAINER(type, name, (node).name.next)

#define SLIST_FOREACH(list, type, name, var) \
    for (type *var = SLIST_HEAD(list, type, name); var != NULL; var = SLIST_NEXT(*var, type, name))

static inline bool slist_empty(slist_t *list) {
    return list->head == NULL;
}

static inline void slist_clear(slist_t *list) {
    list->head = NULL;
}

static inline slist_node_t *slist_remove_head(slist_t *list) {
    slist_node_t *node = list->head;

    if (node) {
        list->head = node->next;
    }

    return node;
}

#define SLIST_REMOVE_HEAD(list, type, name) CONTAINER(type, name, slist_remove_head(&(list)))

static inline void slist_insert_head(slist_t *list, slist_node_t *node) {
    node->next = list->head;

    if (!node->next) list->tail = node;

    list->head = node;
}

static inline void slist_insert_tail(slist_t *list, slist_node_t *node) {
    node->next = NULL;

    if (list->head) list->tail->next = node;
    else list->head = node;

    list->tail = node;
}

static inline void slist_append_end(slist_t *dest, slist_t *src) {
    if (!slist_empty(src)) {
        if (dest->head) dest->tail->next = src->head;
        else dest->head = src->head;

        dest->tail = src->tail;

        src->head = NULL;
    }
}
