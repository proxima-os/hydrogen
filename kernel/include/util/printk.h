#pragma once

#include "arch/irq.h"
#include "proc/sched.h"
#include "util/list.h"
#include <stdarg.h>

typedef struct printk_sink {
    list_node_t node;
    void (*write)(struct printk_sink *self, const void *data, size_t count);
    void (*flush)(struct printk_sink *self);
} printk_sink_t;

typedef struct {
    irq_state_t irq;
    preempt_state_t preempt;
} printk_state_t;

void printk_add(printk_sink_t *sink);
void printk_remove(printk_sink_t *sink);

void vprintk(const char *format, va_list args);
void printk(const char *format, ...);

size_t vsprintk(void *buffer, size_t size, const char *format, va_list args);
size_t sprintk(void *buffer, size_t size, const char *format, ...);

printk_state_t printk_lock(void);
void printk_unlock(printk_state_t state);

// Unlike with vprintk and printk, the caller is responsible for locking when using these functions.
void printk_raw_formatv(const char *format, va_list args);
void printk_raw_format(const char *format, ...);
void printk_raw_write(const void *data, size_t count);
void printk_raw_flush(void);
