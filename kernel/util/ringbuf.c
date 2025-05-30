#include "util/ringbuf.h"
#include "arch/usercopy.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include <hydrogen/limits.h>

#define BUFFER_SIZE __PIPE_BUF

int ringbuf_setup(ringbuf_t *buf) {
    if (!buf->data) {
        buf->data = vmalloc(BUFFER_SIZE);
        if (unlikely(!buf->data)) return ENOMEM;
        buf->read_idx = 0;
        buf->write_idx = 0;
        buf->has_data = false;
    }

    return 0;
}

void ringbuf_free(ringbuf_t *buf) {
    vfree(buf->data, BUFFER_SIZE);
    buf->data = NULL;
}

size_t ringbuf_readable(ringbuf_t *buf) {
    if (!buf->has_data) return 0;

    if (buf->read_idx < buf->write_idx) {
        return buf->write_idx - buf->read_idx;
    } else {
        return (BUFFER_SIZE - buf->read_idx) + buf->write_idx;
    }
}

size_t ringbuf_writable(ringbuf_t *buf) {
    if (!buf->has_data) return BUFFER_SIZE;

    if (buf->read_idx < buf->write_idx) {
        return (BUFFER_SIZE - buf->write_idx) + buf->read_idx;
    } else {
        return buf->read_idx - buf->write_idx;
    }
}

hydrogen_ret_t ringbuf_read(ringbuf_t *buf, void *dest, size_t size) {
    size_t p0_available;
    size_t p1_available;

    if (buf->read_idx < buf->write_idx) {
        p0_available = buf->write_idx - buf->read_idx;
        p1_available = 0;
        if (unlikely(!p0_available)) return ret_integer(0);
    } else {
        p0_available = BUFFER_SIZE - buf->read_idx;
        p1_available = buf->write_idx;
    }

    size_t available = p0_available + p1_available;
    size_t cur_count = size < available ? size : available;
    size_t p0_count = cur_count < p0_available ? cur_count : p0_available;

    int error = user_memcpy(dest, buf->data + buf->read_idx, p0_count);
    if (unlikely(error)) return ret_error(error);

    if (p0_count < cur_count) {
        size_t p1_count = cur_count - p0_count;

        error = user_memcpy(dest + p0_count, buf->data, p1_count);
        if (unlikely(error)) return ret_error(error);

        buf->read_idx = p1_count;
    } else {
        buf->read_idx += p0_count;
        if (buf->read_idx == BUFFER_SIZE) buf->read_idx = 0;
    }

    if (cur_count == available) buf->has_data = false;
    return ret_integer(cur_count);
}

hydrogen_ret_t ringbuf_write(ringbuf_t *buf, const void *src, size_t size) {
    size_t p0_available;
    size_t p1_available;

    if (buf->has_data) {
        if (buf->read_idx < buf->write_idx) {
            p0_available = BUFFER_SIZE - buf->write_idx;
            p1_available = buf->read_idx;
        } else {
            p0_available = buf->read_idx - buf->write_idx;
            p1_available = 0;

            if (unlikely(!p0_available)) return ret_integer(0);
        }
    } else {
        p0_available = BUFFER_SIZE;
        p1_available = 0;
        buf->read_idx = 0;
        buf->write_idx = 0;
    }

    size_t available = p0_available + p1_available;
    size_t cur_count = size < available ? size : available;
    size_t p0_count = cur_count < p0_available ? cur_count : p0_available;

    int error = user_memcpy(buf->data + buf->write_idx, src, p0_count);
    if (unlikely(error)) return ret_error(error);

    if (p0_count < cur_count) {
        size_t p1_count = cur_count - p0_count;

        error = user_memcpy(buf->data, src + p0_count, p1_count);
        if (unlikely(error)) return ret_error(error);

        buf->write_idx = p1_count;
    } else {
        buf->write_idx += p0_count;
        if (buf->write_idx == BUFFER_SIZE) buf->write_idx = 0;
    }

    buf->has_data = true;
    return ret_integer(cur_count);
}
