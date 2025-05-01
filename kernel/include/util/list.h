#pragma once

#include "kernel/compiler.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct list_node {
    struct list_node *prev;
    struct list_node *next;
} list_node_t;

typedef struct {
    list_node_t *head;
    list_node_t *tail;
} list_t;

#define LIST_HEAD(list, type, name) CONTAINER(type, name, (list).head)
#define LIST_TAIL(list, type, name) CONTAINER(type, name, (list).tail)
#define LIST_PREV(node, type, name) CONTAINER(type, name, (node).name.prev)
#define LIST_NEXT(node, type, name) CONTAINER(type, name, (node).name.next)

#define LIST_FOREACH(list, type, name, var) \
    for (type *var = LIST_HEAD(list, type, name); var != NULL; var = LIST_NEXT(*var, type, name))

static inline bool list_empty(list_t *list) {
    return list->head == NULL;
}

static inline void list_clear(list_t *list) {
    list->head = NULL;
    list->tail = NULL;
}

static inline void list_remove(list_t *list, list_node_t *node) {
    if (node->prev) node->prev->next = node->next;
    else list->head = node->next;

    if (node->next) node->next->prev = node->prev;
    else list->tail = node->prev;
}

static inline list_node_t *list_remove_head(list_t *list) {
    list_node_t *node = list->head;

    if (node) {
        list->head = node->next;

        if (node->next) node->next->prev = NULL;
        else list->tail = NULL;
    }

    return node;
}

static inline list_node_t *list_remove_tail(list_t *list) {
    list_node_t *node = list->tail;

    if (node) {
        list->tail = node->prev;

        if (node->prev) node->prev->next = NULL;
        else list->head = NULL;
    }

    return node;
}

#define LIST_REMOVE_HEAD(list, type, name) CONTAINER(type, name, list_remove_head(&(list)))
#define LIST_REMOVE_TAIL(list, type, name) CONTAINER(type, name, list_remove_tail(&(list)))

static inline void list_insert_head(list_t *list, list_node_t *node) {
    node->prev = NULL;
    node->next = list->head;

    if (node->next) node->next->prev = node;
    else list->tail = node;
}

static inline void list_insert_tail(list_t *list, list_node_t *node) {
    node->prev = list->tail;
    node->next = NULL;

    if (node->prev) node->prev->next = node;
    else list->head = node;
}

static inline void list_insert_before(list_t *list, list_node_t *anchor, list_node_t *node) {
    node->next = anchor;

    if (anchor) {
        node->prev = anchor->prev;
        anchor->prev = node;
    } else {
        node->prev = list->tail;
        list->tail = node;
    }

    if (node->prev) node->prev->next = node;
    else list->head = node;
}

static inline void list_insert_after(list_t *list, list_node_t *anchor, list_node_t *node) {
    node->prev = anchor;

    if (anchor) {
        node->next = anchor->next;
        anchor->next = node;
    } else {
        node->next = list->head;
        list->head = node;
    }

    if (node->next) node->next->prev = node;
    else list->tail = node;
}
