#include "fs/fifo.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "fs/vfs.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "proc/mutex.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "util/eventqueue.h"
#include "util/list.h"
#include "util/ringbuf.h"
#include <hydrogen/eventqueue.h>
#include <hydrogen/fcntl.h>
#include <hydrogen/limits.h>
#include <hydrogen/signal.h>
#include <hydrogen/types.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    file_t base;
    list_node_t node;
    event_source_t readable_event;
    event_source_t writable_event;
    event_source_t disconnect_event;
} fifo_file_t;

static int fifo_wait(fifo_t *fifo, list_t *list, inode_t *inode) {
    list_insert_tail(list, &current_thread->wait_node);
    sched_prepare_wait(true);
    mutex_rel(&fifo->lock);
    if (inode) mutex_rel(&inode->lock);

    int error = sched_perform_wait(0);

    mutex_acq(&fifo->lock, 0, false);
    if (inode) mutex_acq(&inode->lock, 0, false);
    if (unlikely(error)) list_remove(list, &current_thread->wait_node);
    return error;
}

static void fifo_awaken(list_t *list) {
    thread_t *cur = LIST_HEAD(*list, thread_t, wait_node);

    while (cur) {
        thread_t *next = LIST_NEXT(*cur, thread_t, wait_node);
        if (sched_wake(cur)) list_remove(list, &cur->wait_node);
        cur = next;
    }
}

static void fifo_file_free(object_t *ptr) {
    fifo_file_t *self = (fifo_file_t *)ptr;
    fifo_t *fifo = &self->base.inode->fifo;
    mutex_acq(&fifo->lock, 0, false);

    list_remove(&fifo->files, &self->node);

    if ((self->base.flags & __O_RDONLY) != 0 && --fifo->num_readers == 0) {
        fifo_awaken(&fifo->write_waiting);
    }

    if ((self->base.flags & __O_WRONLY) != 0 && --fifo->num_writers == 0) {
        fifo_awaken(&fifo->read_waiting);

        LIST_FOREACH(fifo->files, fifo_file_t, node, file) {
            event_source_signal(&file->disconnect_event);
        }
    }

    mutex_rel(&fifo->lock);

    event_source_cleanup(&self->readable_event);
    event_source_cleanup(&self->writable_event);
    event_source_cleanup(&self->disconnect_event);
    free_file(&self->base);
    vfree(self, sizeof(*self));
}

static int fifo_file_event_add(object_t *ptr, uint32_t rights, active_event_t *event) {
    fifo_file_t *self = (fifo_file_t *)ptr;

    switch (event->source.type) {
    case HYDROGEN_EVENT_FILE_DESCRIPTION_READABLE: return event_source_add(&self->readable_event, event);
    case HYDROGEN_EVENT_FILE_DESCRIPTION_WRITABLE: return event_source_add(&self->writable_event, event);
    case HYDROGEN_EVENT_FILE_DESCRIPTION_DISCONNECTED: return event_source_add(&self->disconnect_event, event);
    default: return EINVAL;
    }
}

static void fifo_file_event_del(object_t *ptr, active_event_t *event) {
    fifo_file_t *self = (fifo_file_t *)ptr;

    switch (event->source.type) {
    case HYDROGEN_EVENT_FILE_DESCRIPTION_READABLE: event_source_del(&self->readable_event, event); break;
    case HYDROGEN_EVENT_FILE_DESCRIPTION_WRITABLE: event_source_del(&self->writable_event, event); break;
    case HYDROGEN_EVENT_FILE_DESCRIPTION_DISCONNECTED: event_source_del(&self->disconnect_event, event); break;
    default: UNREACHABLE();
    }
}

static hydrogen_ret_t fifo_file_read(file_t *ptr, void *buffer, size_t size, uint64_t position) {
    fifo_file_t *self = (fifo_file_t *)ptr;
    fifo_t *fifo = &self->base.inode->fifo;

    mutex_acq(&fifo->lock, 0, false);

    size_t readable = ringbuf_readable(&fifo->buffer);

    while (!readable) {
        if (fifo->num_writers == 0) {
            mutex_rel(&fifo->lock);
            return ret_integer(0);
        }

        if (self->base.flags & __O_NONBLOCK) {
            mutex_rel(&fifo->lock);
            return ret_error(EAGAIN);
        }

        int error = fifo_wait(fifo, &fifo->read_waiting, NULL);
        if (unlikely(error)) {
            mutex_rel(&fifo->lock);
            return ret_error(error);
        }

        readable = ringbuf_readable(&fifo->buffer);
    }

    size_t writable = ringbuf_writable(&fifo->buffer);

    hydrogen_ret_t ret = ringbuf_read(&fifo->buffer, buffer, size);
    if (unlikely(ret.error)) {
        mutex_rel(&fifo->lock);
        return ret;
    }

    bool reset_read = ret.integer == readable;
    bool signal_write = writable == 0;

    if (signal_write) fifo_awaken(&fifo->write_waiting);

    if (reset_read || signal_write) {
        LIST_FOREACH(fifo->files, fifo_file_t, node, file) {
            if (reset_read) event_source_reset(&file->readable_event);
            if (signal_write) event_source_signal(&file->writable_event);
        }
    }

    mutex_rel(&fifo->lock);
    return ret;
}

static hydrogen_ret_t fifo_file_write(file_t *ptr, const void *buffer, size_t size, uint64_t position, bool rpos) {
    fifo_file_t *self = (fifo_file_t *)ptr;
    fifo_t *fifo = &self->base.inode->fifo;
    mutex_acq(&fifo->lock, 0, false);

    size_t total = 0;

    do {
        if (fifo->num_readers == 0) {
            mutex_rel(&fifo->lock);
            __siginfo_t sig = {
                .__signo = __SIGPIPE,
            };
            queue_signal(current_thread->process, &current_thread->sig_target, &sig, 0, &current_thread->pipe_sig);
            return ret_error(EPIPE);
        }

        size_t writable = ringbuf_writable(&fifo->buffer);

        if (writable < size) {
            if (self->base.flags & __O_NONBLOCK) {
                if (total != 0) break;

                if (size <= __PIPE_BUF || writable == 0) {
                    mutex_rel(&fifo->lock);
                    return ret_error(EAGAIN);
                }
            } else if (writable == 0) {
                int error = fifo_wait(fifo, &fifo->write_waiting, NULL);

                if (unlikely(error)) {
                    if (total != 0) break;

                    mutex_rel(&fifo->lock);
                    return ret_error(error);
                }

                continue;
            }
        }

        size_t readable = ringbuf_readable(&fifo->buffer);

        hydrogen_ret_t ret = ringbuf_write(&fifo->buffer, buffer, size);
        if (unlikely(ret.error)) {
            if (total) break;
            mutex_rel(&fifo->lock);
            return ret;
        }

        bool reset_write = ret.integer == writable;
        bool signal_read = readable == 0;

        if (signal_read) fifo_awaken(&fifo->read_waiting);

        if (reset_write || signal_read) {
            LIST_FOREACH(fifo->files, fifo_file_t, node, file) {
                if (reset_write) event_source_reset(&file->writable_event);
                if (signal_read) event_source_signal(&file->readable_event);
            }
        }

        total += ret.integer;
        buffer += ret.integer;
        size -= ret.integer;
    } while (size != 0 && (self->base.flags & __O_NONBLOCK) == 0);

    mutex_rel(&fifo->lock);
    return ret_integer(total);
}

static const file_ops_t fifo_file_ops = {
    .base.free = fifo_file_free,
    .base.event_add = fifo_file_event_add,
    .base.event_del = fifo_file_event_del,
    .read = fifo_file_read,
    .write = fifo_file_write,
};

hydrogen_ret_t fifo_open(fifo_t *fifo, inode_t *inode, dentry_t *path, int flags) {
    ASSERT(fifo == &inode->fifo);
    mutex_acq(&fifo->lock, 0, false);

    int error = ringbuf_setup(&fifo->buffer, __PIPE_BUF);
    if (unlikely(error)) {
        mutex_rel(&fifo->lock);
        return ret_error(error);
    }

    switch (flags & (__O_RDONLY | __O_WRONLY)) {
    case __O_RDONLY:
        if ((flags & __O_NONBLOCK) == 0) {
            while (fifo->num_writers == 0) {
                int error = fifo_wait(fifo, &fifo->open_write_waiting, inode);

                if (unlikely(error)) {
                    mutex_rel(&fifo->lock);
                    return ret_error(error);
                }
            }
        }
        break;
    case __O_WRONLY:
        while (fifo->num_readers == 0) {
            if (flags & __O_NONBLOCK) {
                mutex_rel(&fifo->lock);
                return ret_error(ENXIO);
            }

            int error = fifo_wait(fifo, &fifo->open_read_waiting, inode);

            if (unlikely(error)) {
                mutex_rel(&fifo->lock);
                return ret_error(error);
            }
        }
        break;
    default: break;
    }

    fifo_file_t *file = vmalloc(sizeof(*file));
    if (unlikely(!file)) {
        mutex_rel(&fifo->lock);
        return ret_error(ENOMEM);
    }
    memset(file, 0, sizeof(*file));

    init_file(&file->base, &fifo_file_ops, inode, path, flags);

    if (flags & __O_RDONLY) {
        fifo->num_readers += 1;
        fifo_awaken(&fifo->open_read_waiting);
    }

    if (flags & __O_WRONLY) {
        fifo_awaken(&fifo->open_write_waiting);

        if (fifo->num_writers++ == 0) {
            LIST_FOREACH(fifo->files, fifo_file_t, node, file) {
                event_source_reset(&file->disconnect_event);
            }
        }
    }

    if (ringbuf_readable(&fifo->buffer)) event_source_signal(&file->readable_event);
    if (ringbuf_writable(&fifo->buffer)) event_source_signal(&file->writable_event);
    if (fifo->num_writers == 0) event_source_signal(&file->disconnect_event);

    list_insert_tail(&fifo->files, &file->node);

    mutex_rel(&fifo->lock);
    return ret_pointer(file);
}

void fifo_free(fifo_t *fifo) {
    ringbuf_free(&fifo->buffer);
}
