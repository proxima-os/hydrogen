#include "fs/fifo.h"
#include "arch/usercopy.h"
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

    while (!fifo->has_data) {
        if (fifo->num_writers == 0) {
            mutex_rel(&fifo->lock);
            return ret_integer(0);
        }

        if (self->base.flags & __O_NONBLOCK) {
            mutex_rel(&fifo->lock);
            return ret_error(EAGAIN);
        }

        fifo_wait(fifo, &fifo->read_waiting, NULL);
    }

    bool is_split = fifo->read_idx >= fifo->write_idx;
    size_t p0_available = is_split ? __PIPE_BUF - fifo->read_idx : fifo->write_idx - fifo->read_idx;
    size_t p1_available = is_split ? fifo->write_idx : 0;
    size_t available = p0_available + p1_available;
    size_t cur_count = size < available ? size : available;
    size_t p0_count = cur_count < p0_available ? cur_count : p0_available;

    int error = user_memcpy(buffer, fifo->buffer + fifo->read_idx, p0_count);

    if (unlikely(error)) {
        mutex_rel(&fifo->lock);
        return ret_error(error);
    }

    if (p0_count < cur_count) {
        size_t p1_count = cur_count - p0_count;
        error = user_memcpy(buffer + p0_count, fifo->buffer, p1_count);

        if (unlikely(error)) {
            mutex_rel(&fifo->lock);
            return ret_error(error);
        }

        fifo->read_idx = p1_count;
    } else {
        fifo->read_idx += p0_count;
        if (fifo->read_idx == __PIPE_BUF) fifo->read_idx = 0;
    }

    bool reset_read = cur_count == available;
    bool signal_write = available == __PIPE_BUF;

    if (reset_read) fifo->has_data = false;
    if (signal_write) fifo_awaken(&fifo->write_waiting);

    if (reset_read || signal_write) {
        LIST_FOREACH(fifo->files, fifo_file_t, node, file) {
            if (reset_read) event_source_reset(&file->readable_event);
            if (signal_write) event_source_signal(&file->writable_event);
        }
    }

    mutex_rel(&fifo->lock);
    return ret_integer(cur_count);
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

        size_t p0_available;
        size_t p1_available;

        if (fifo->has_data) {
            bool is_split = fifo->read_idx < fifo->write_idx;
            p0_available = is_split ? __PIPE_BUF - fifo->write_idx : fifo->read_idx - fifo->write_idx;
            p1_available = is_split ? fifo->read_idx : 0;
        } else {
            p0_available = __PIPE_BUF - fifo->write_idx;
            p1_available = fifo->write_idx;
        }

        size_t available = p0_available + p1_available;

        if (available < size) {
            if (self->base.flags & __O_NONBLOCK) {
                if (size <= __PIPE_BUF || available == 0) {
                    mutex_rel(&fifo->lock);
                    return ret_error(EAGAIN);
                }
            } else if (available == 0) {
                int error = fifo_wait(fifo, &fifo->write_waiting, NULL);

                if (unlikely(error)) {
                    if (total != 0) break;

                    mutex_rel(&fifo->lock);
                    return ret_error(error);
                }

                continue;
            }
        }

        size_t cur_count = size < available ? size : available;
        size_t p0_count = cur_count < p0_available ? cur_count : p0_available;

        int error = user_memcpy(fifo->buffer + fifo->write_idx, buffer, p0_count);

        if (unlikely(error)) {
            mutex_rel(&fifo->lock);
            return ret_error(error);
        }

        if (p0_count < cur_count) {
            size_t p1_count = cur_count - p0_count;
            error = user_memcpy(fifo->buffer, buffer + p0_count, p1_count);

            if (unlikely(error)) {
                mutex_rel(&fifo->lock);
                return ret_error(error);
            }

            fifo->write_idx = p1_count;
        } else {
            fifo->write_idx += p0_count;
            if (fifo->write_idx == __PIPE_BUF) fifo->write_idx = 0;
        }

        bool reset_write = cur_count == available;
        bool signal_read = available == __PIPE_BUF;

        if (signal_read) {
            fifo->has_data = true;
            fifo_awaken(&fifo->read_waiting);
        }

        if (reset_write || signal_read) {
            LIST_FOREACH(fifo->files, fifo_file_t, node, file) {
                if (reset_write) event_source_reset(&file->writable_event);
                if (signal_read) event_source_signal(&file->readable_event);
            }
        }
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

    if (!fifo->buffer) {
        fifo->buffer = vmalloc(__PIPE_BUF);
        if (unlikely(!fifo->buffer)) {
            mutex_rel(&fifo->lock);
            return ret_error(ENOMEM);
        }
        fifo->read_idx = 0;
        fifo->write_idx = 0;
        fifo->has_data = false;
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
        fifo->num_writers += 1;
        fifo_awaken(&fifo->open_write_waiting);

        if (fifo->num_writers++ == 0) {
            LIST_FOREACH(fifo->files, fifo_file_t, node, file) {
                event_source_reset(&file->disconnect_event);
            }
        }
    }

    if (fifo->has_data) event_source_signal(&file->readable_event);
    if (!fifo->has_data || fifo->read_idx != fifo->write_idx) event_source_signal(&file->writable_event);
    if (fifo->num_writers == 0) event_source_signal(&file->disconnect_event);

    list_insert_tail(&fifo->files, &file->node);

    mutex_rel(&fifo->lock);
    return ret_pointer(file);
}

void fifo_free(fifo_t *fifo) {
    vfree(fifo->buffer, __PIPE_BUF);
}
