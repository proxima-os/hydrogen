#pragma once

#include <hydrogen/types.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    unsigned char *data;
    size_t read_idx;
    size_t write_idx;
    bool has_data;
} ringbuf_t;

int ringbuf_setup(ringbuf_t *buf);
void ringbuf_free(ringbuf_t *buf);

size_t ringbuf_readable(ringbuf_t *buf);
size_t ringbuf_writable(ringbuf_t *buf);

hydrogen_ret_t ringbuf_read(ringbuf_t *buf, void *dest, size_t size);
hydrogen_ret_t ringbuf_write(ringbuf_t *buf, const void *src, size_t size);
