#pragma once

#include "proc/mutex.h"
#include "util/list.h"
#include "util/ringbuf.h"
#include <hydrogen/types.h>
#include <stddef.h>

struct inode;
struct dentry;

typedef struct {
    ringbuf_t buffer;

    list_t read_waiting;
    list_t write_waiting;

    list_t open_read_waiting;
    list_t open_write_waiting;

    list_t files;
    size_t num_readers;
    size_t num_writers;

    mutex_t lock;
} fifo_t;

hydrogen_ret_t fifo_open(fifo_t *fifo, struct inode *inode, struct dentry *path, int flags);
void fifo_free(fifo_t *fifo);
