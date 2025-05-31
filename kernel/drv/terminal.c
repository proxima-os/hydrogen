#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "fs/vfs.h"
#include "init/main.h" /* IWYU pragma: keep */
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "kernel/return.h"
#include "kernel/types.h"
#include "mem/vmalloc.h"
#include "proc/mutex.h"
#include "proc/process.h"
#include "string.h"
#include "sys/filesystem.h"
#include "util/eventqueue.h"
#include "util/handle.h"
#include "util/list.h"
#include "util/object.h"
#include "util/panic.h"
#include "util/refcount.h"
#include "util/ringbuf.h"
#include "util/time.h"
#include <hydrogen/eventqueue.h>
#include <hydrogen/fcntl.h>
#include <hydrogen/filesystem.h>
#include <hydrogen/ioctl.h>
#include <hydrogen/stat.h>
#include <hydrogen/termios.h>
#include <hydrogen/types.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    fs_device_t base;
    inode_t inode;
    unsigned index;
    bool have_inode_ref;
    bool locked;

    mutex_t files_lock;
    list_t files;
    bool have_master;

    mutex_t rx_lock;
    ringbuf_t rx;
    list_t rx_read_waiting;
    list_t rx_write_waiting;
    event_source_t rx_writable_event;

    mutex_t tx_lock;
    ringbuf_t tx;
    list_t tx_read_waiting;
    list_t tx_write_waiting;
    event_source_t tx_readable_event;
    struct __termios settings;
    unsigned column;
} pty_t;

static int pty_wait(list_t *list, mutex_t *lock) {
    list_insert_tail(list, &current_thread->wait_node);
    sched_prepare_wait(true);
    if (lock) mutex_rel(lock);

    int error = sched_perform_wait(0);

    if (lock) mutex_acq(lock, 0, false);
    if (unlikely(error)) list_remove(list, &current_thread->wait_node);
    return error;
}

static void pty_wake(list_t *list) {
    thread_t *cur = LIST_HEAD(*list, thread_t, wait_node);

    while (cur) {
        thread_t *next = LIST_NEXT(*cur, thread_t, wait_node);
        if (sched_wake(cur)) list_remove(list, &cur->wait_node);
        cur = next;
    }
}

typedef struct {
    file_t base;
    pty_t *pty;
} ptm_file_t;

typedef struct {
    file_t base;
    list_node_t node;
    event_source_t readable_event;
    event_source_t writable_event;
    event_source_t disconnect_event;
} pts_file_t;

static hydrogen_ret_t pty_ioctl(pty_t *pty, int request, void *buffer, size_t size) {
    switch (request) {
    case __IOCTL_PTY_GET_SETTINGS: {
        struct __termios data;
        if (unlikely(size < sizeof(data))) return ret_error(EINVAL);

        mutex_acq(&pty->rx_lock, 0, false);
        data = pty->settings;
        mutex_rel(&pty->rx_lock);

        int error = user_memcpy(buffer, &data, sizeof(data));
        if (unlikely(error)) return ret_error(error);

        return ret_error(0);
    }
    case __IOCTL_PTY_SET_SETTINGS:
    case __IOCTL_PTY_SET_SETTINGS_DRAIN:
    case __IOCTL_PTY_SET_SETTINGS_FLUSH: {
        struct __termios data;
        if (unlikely(size < sizeof(data))) return ret_error(EINVAL);

        // Note: drain is identical to regular, because "data has been sent" means "data is in tx buffer" for ptys

        mutex_acq(&pty->rx_lock, 0, false);
        mutex_acq(&pty->tx_lock, 0, false);

        if (request == __IOCTL_PTY_SET_SETTINGS_FLUSH && ringbuf_readable(&pty->rx)) {
            ringbuf_clear(&pty->rx);
            event_source_signal(&pty->rx_writable_event);
            mutex_acq(&pty->files_lock, 0, false);

            LIST_FOREACH(pty->files, pts_file_t, node, file) {
                event_source_reset(&file->readable_event);
            }

            mutex_rel(&pty->files_lock);
        }

        data = pty->settings;

        mutex_rel(&pty->tx_lock);
        mutex_rel(&pty->rx_lock);

        int error = user_memcpy(buffer, &data, sizeof(data));
        if (unlikely(error)) return ret_error(error);

        return ret_error(0);
    }
    default: return ret_error(ENOTTY);
    }
}

static void ptm_free(object_t *ptr) {
    ptm_file_t *self = (ptm_file_t *)ptr;
    free_file(&self->base);

    mutex_acq(&self->pty->files_lock, 0, false);
    self->pty->have_master = false;

    LIST_FOREACH(self->pty->files, pts_file_t, node, file) {
        event_source_signal(&file->disconnect_event);
    }

    mutex_rel(&self->pty->files_lock);
    vfree(self, sizeof(*self));
}

static int ptm_event_add(object_t *ptr, object_rights_t rights, active_event_t *event) {
    ptm_file_t *self = (ptm_file_t *)ptr;

    switch (event->source.type) {
    case HYDROGEN_EVENT_FILE_DESCRIPTION_READABLE: return event_source_add(&self->pty->tx_readable_event, event);
    case HYDROGEN_EVENT_FILE_DESCRIPTION_WRITABLE: return event_source_add(&self->pty->rx_writable_event, event);
    case HYDROGEN_EVENT_FILE_DESCRIPTION_DISCONNECTED: return 0;
    default: return EINVAL;
    }
}

static void ptm_event_del(object_t *ptr, active_event_t *event) {
    ptm_file_t *self = (ptm_file_t *)ptr;

    switch (event->source.type) {
    case HYDROGEN_EVENT_FILE_DESCRIPTION_READABLE: return event_source_del(&self->pty->tx_readable_event, event);
    case HYDROGEN_EVENT_FILE_DESCRIPTION_WRITABLE: return event_source_del(&self->pty->rx_writable_event, event);
    case HYDROGEN_EVENT_FILE_DESCRIPTION_DISCONNECTED: return;
    default: UNREACHABLE();
    }
}

static hydrogen_ret_t ptm_read(file_t *ptr, void *buffer, size_t size, uint64_t position) {
    ptm_file_t *self = (ptm_file_t *)ptr;
    pty_t *pty = self->pty;
    mutex_acq(&pty->tx_lock, 0, false);

    size_t readable = ringbuf_readable(&pty->tx);

    while (!readable) {
        if (self->base.flags & __O_NONBLOCK) {
            mutex_rel(&pty->tx_lock);
            return ret_error(EAGAIN);
        }

        int error = pty_wait(&pty->tx_read_waiting, &pty->tx_lock);
        if (unlikely(error)) {
            mutex_rel(&pty->tx_lock);
            return ret_error(error);
        }

        readable = ringbuf_readable(&pty->tx);
    }

    size_t writable = ringbuf_writable(&pty->tx);

    hydrogen_ret_t ret = ringbuf_read(&pty->tx, buffer, size);
    if (unlikely(ret.error)) {
        mutex_rel(&pty->tx_lock);
        return ret;
    }

    if (readable == ret.integer) {
        event_source_reset(&pty->tx_readable_event);
    }

    if (writable == 0) {
        pty_wake(&pty->tx_write_waiting);
        mutex_acq(&pty->files_lock, 0, false);

        LIST_FOREACH(pty->files, pts_file_t, node, file) {
            event_source_signal(&file->writable_event);
        }

        mutex_rel(&pty->files_lock);
    }

    mutex_rel(&pty->tx_lock);
    return ret;
}

static hydrogen_ret_t ptm_write(file_t *ptr, const void *buffer, size_t size, uint64_t position, bool rpos) {
    ptm_file_t *self = (ptm_file_t *)ptr;
    pty_t *pty = self->pty;
    mutex_acq(&pty->rx_lock, 0, false);

    size_t writable = ringbuf_writable(&pty->rx);

    while (!writable) {
        if (self->base.flags & __O_NONBLOCK) {
            mutex_rel(&pty->rx_lock);
            return ret_error(EAGAIN);
        }

        int error = pty_wait(&pty->rx_write_waiting, &pty->rx_lock);
        if (unlikely(error)) {
            mutex_rel(&pty->rx_lock);
            return ret_error(error);
        }

        writable = ringbuf_writable(&pty->rx);
    }

    size_t readable = ringbuf_readable(&pty->rx);

    hydrogen_ret_t ret = ringbuf_write(&pty->rx, buffer, size);
    if (unlikely(ret.error)) {
        mutex_rel(&pty->rx_lock);
        return ret;
    }

    if (writable == ret.integer) {
        event_source_reset(&pty->rx_writable_event);
    }

    if (readable == 0) {
        pty_wake(&pty->rx_read_waiting);
        mutex_acq(&pty->files_lock, 0, false);

        LIST_FOREACH(pty->files, pts_file_t, node, file) {
            event_source_signal(&file->readable_event);
        }

        mutex_rel(&pty->files_lock);
    }

    mutex_rel(&pty->rx_lock);
    return ret;
}

static hydrogen_ret_t ptm_ioctl(file_t *ptr, int request, void *buffer, size_t size) {
    ptm_file_t *self = (ptm_file_t *)ptr;
    pty_t *pty = self->pty;

    switch (request) {
    case __IOCTL_PTM_GET_NUMBER: return ret_integer(pty->index);
    case __IOCTL_PTM_OPEN_SLAVE: {
        int data;
        if (unlikely(size < sizeof(data))) return ret_error(EINVAL);

        int error = user_memcpy(&data, buffer, sizeof(data));
        if (unlikely(error)) return ret_error(error);

        error = hnd_reserve(current_thread->namespace);
        if (unlikely(error)) return ret_error(error);

        handle_data_t *hdata = vmalloc(sizeof(*hdata));
        if (unlikely(!hdata)) {
            hnd_unreserve(current_thread->namespace);
            return ret_error(ENOMEM);
        }

        file_t *file;
        ident_t *ident = ident_get(current_thread->process);
        error = vfs_fopen(&file, NULL, &pty->inode, data, ident);
        ident_deref(ident);
        if (unlikely(error)) {
            vfree(hdata, sizeof(*hdata));
            hnd_unreserve(current_thread->namespace);
            return ret_error(error);
        }

        int fd = hnd_alloc_reserved(
            current_thread->namespace,
            &file->base,
            get_open_rights(data),
            get_open_flags(data),
            hdata
        );
        obj_deref(&file->base);
        return ret_integer(fd);
    }
    case __IOCTL_PTM_GET_LOCKED: return ret_integer(__atomic_load_n(&pty->locked, __ATOMIC_ACQUIRE));
    case __IOCTL_PTM_SET_LOCKED: {
        if (unlikely((self->base.flags & __O_WRONLY) != __O_WRONLY)) return ret_error(EBADF);

        int data;
        if (unlikely(size < sizeof(data))) return ret_error(EINVAL);

        int error = user_memcpy(&data, buffer, sizeof(data));
        if (unlikely(error)) return ret_error(error);

        __atomic_store_n(&pty->locked, !!data, __ATOMIC_RELEASE);
        return ret_error(0);
    }
    default: return pty_ioctl(pty, request, buffer, size);
    }
}

static const file_ops_t ptm_ops = {
    .base.free = ptm_free,
    .base.event_add = ptm_event_add,
    .base.event_del = ptm_event_del,
    .read = ptm_read,
    .write = ptm_write,
    .ioctl = ptm_ioctl,
};

static void pts_free(object_t *ptr) {
    pts_file_t *self = (pts_file_t *)ptr;
    free_file(&self->base);
    event_source_cleanup(&self->readable_event);
    event_source_cleanup(&self->writable_event);
    event_source_cleanup(&self->disconnect_event);
    vfree(self, sizeof(*self));
}

static int pts_event_add(object_t *ptr, object_rights_t rights, active_event_t *event) {
    pts_file_t *self = (pts_file_t *)ptr;

    switch (event->source.type) {
    case HYDROGEN_EVENT_FILE_DESCRIPTION_READABLE: return event_source_add(&self->readable_event, event);
    case HYDROGEN_EVENT_FILE_DESCRIPTION_WRITABLE: return event_source_add(&self->writable_event, event);
    case HYDROGEN_EVENT_FILE_DESCRIPTION_DISCONNECTED: return event_source_add(&self->disconnect_event, event);
    default: return EINVAL;
    }
}

static void pts_event_del(object_t *ptr, active_event_t *event) {
    pts_file_t *self = (pts_file_t *)ptr;

    switch (event->source.type) {
    case HYDROGEN_EVENT_FILE_DESCRIPTION_READABLE: return event_source_del(&self->readable_event, event);
    case HYDROGEN_EVENT_FILE_DESCRIPTION_WRITABLE: return event_source_del(&self->writable_event, event);
    case HYDROGEN_EVENT_FILE_DESCRIPTION_DISCONNECTED: return event_source_del(&self->disconnect_event, event);
    default: UNREACHABLE();
    }
}

static hydrogen_ret_t pts_read(file_t *ptr, void *buffer, size_t size, uint64_t position) {
    pts_file_t *self = (pts_file_t *)ptr;
    pty_t *pty = (pty_t *)self->base.inode->device;

    mutex_acq(&pty->rx_lock, 0, false);

    size_t readable = ringbuf_readable(&pty->rx);

    while (!readable) {
        if (self->base.flags & __O_NONBLOCK) {
            mutex_rel(&pty->rx_lock);
            return ret_error(EAGAIN);
        }

        int error = pty_wait(&pty->rx_read_waiting, &pty->rx_lock);
        if (unlikely(error)) {
            mutex_rel(&pty->rx_lock);
            return ret_error(error);
        }

        readable = ringbuf_readable(&pty->rx);
    }

    size_t writable = ringbuf_writable(&pty->rx);

    hydrogen_ret_t ret = ringbuf_read(&pty->rx, buffer, size);
    if (unlikely(ret.error)) {
        mutex_rel(&pty->rx_lock);
        return ret;
    }

    if (readable == ret.integer) {
        mutex_acq(&pty->files_lock, 0, false);

        LIST_FOREACH(pty->files, pts_file_t, node, file) {
            event_source_reset(&file->readable_event);
        }

        mutex_rel(&pty->files_lock);
    }

    if (writable == 0) {
        pty_wake(&pty->rx_write_waiting);
        event_source_signal(&pty->rx_writable_event);
    }

    mutex_rel(&pty->rx_lock);
    return ret;
}

static ssize_t process_single_char(pty_t *pty, unsigned char c, size_t available) {
    ASSERT(available != 0);

    switch (c) {
    case '\n':
        if (pty->settings.__output_flags & __ONLCR) {
            if (available < 2) return -1;
            ringbuf_put(&pty->tx, '\r');
            ringbuf_put(&pty->tx, '\n');
            pty->column = 0;
            return 2;
        }

        if (pty->settings.__output_flags & __ONLRET) pty->column = 0;
        break;
    case '\r':
        if ((pty->settings.__output_flags & __ONOCR) != 0 && pty->column == 0) return 0;

        if (pty->settings.__output_flags & __OCRNL) {
            c = '\n';
            if (pty->settings.__output_flags & __ONLRET) pty->column = 0;
            break;
        }

        pty->column = 0;
        break;
    case '\t': {
        unsigned spaces = 8 - (pty->column & 7);

        if ((pty->settings.__output_flags & __TABDLY) == __TAB3) {
            if (available < spaces) return -1;

            pty->column += spaces;
            for (unsigned i = 0; i < spaces; i++) ringbuf_put(&pty->tx, ' ');

            return spaces;
        }

        pty->column += spaces;
        break;
    }
    case '\b':
        if (pty->column) pty->column -= 1;
        break;
    default:
        if (c >= 0x20 && c != 0x7f && ((pty->settings.__input_flags & __IUTF8) == 0 || (c & 0xc0) != 0x80)) {
            pty->column += 1;
        }
        break;
    }

    ringbuf_put(&pty->tx, c);
    return 1;
}

typedef struct {
    size_t written;
    size_t processed;
} process_result_t;

static int process_user_buffer(process_result_t *out, pty_t *pty, const void *buffer, size_t size, size_t available) {
    process_result_t result = {};
    unsigned char buf[1024];

    while (size > 0 && available > 0) {
        size_t cur = sizeof(buf) < size ? sizeof(buf) : size;
        int error = user_memcpy(buf, buffer, cur);
        if (unlikely(error)) {
            if (result.processed) break;
            return error;
        }

        for (size_t i = 0; i < cur && available > 0; i++) {
            ssize_t count = process_single_char(pty, buf[i], available);
            if (count < 0) goto done;
            result.processed += 1;
            result.written += count;
            available -= count;
        }

        buffer += cur;
        size -= cur;
    }

done:
    *out = result;
    return 0;
}

static hydrogen_ret_t pts_write(file_t *ptr, const void *buffer, size_t size, uint64_t position, bool rpos) {
    pts_file_t *self = (pts_file_t *)ptr;
    pty_t *pty = (pty_t *)self->base.inode->device;

    mutex_acq(&pty->tx_lock, 0, false);

    size_t writable = ringbuf_writable(&pty->tx);

    while (!writable) {
        if (self->base.flags & __O_NONBLOCK) {
            mutex_rel(&pty->tx_lock);
            return ret_error(EAGAIN);
        }

        int error = pty_wait(&pty->tx_write_waiting, &pty->tx_lock);
        if (unlikely(error)) {
            mutex_rel(&pty->tx_lock);
            return ret_error(error);
        }

        writable = ringbuf_writable(&pty->tx);
    }

    size_t readable = ringbuf_readable(&pty->tx);
    process_result_t result;

    if (pty->settings.__output_flags & __OPOST) {
        int error = process_user_buffer(&result, pty, buffer, size, writable);
        if (unlikely(error)) {
            mutex_rel(&pty->tx_lock);
            return ret_error(error);
        }
    } else {
        hydrogen_ret_t ret = ringbuf_write(&pty->tx, buffer, size);
        if (unlikely(ret.error)) {
            mutex_rel(&pty->tx_lock);
            return ret;
        }
        result.written = ret.integer;
        result.processed = ret.integer;
    }

    if (writable == result.written) {
        mutex_acq(&pty->files_lock, 0, false);

        LIST_FOREACH(pty->files, pts_file_t, node, file) {
            event_source_reset(&file->writable_event);
        }

        mutex_rel(&pty->files_lock);
    }

    if (readable == 0 && result.written != 0) {
        pty_wake(&pty->tx_read_waiting);
        event_source_signal(&pty->tx_readable_event);
    }

    mutex_rel(&pty->tx_lock);
    return ret_integer(result.processed);
}

static hydrogen_ret_t pts_ioctl(file_t *ptr, int request, void *buffer, size_t size) {
    pts_file_t *self = (pts_file_t *)ptr;
    pty_t *pty = (pty_t *)self->base.inode->device;

    return pty_ioctl(pty, request, buffer, size);
}

static const file_ops_t pts_ops = {
    .base.free = pts_free,
    .base.event_add = pts_event_add,
    .base.event_del = pts_event_del,
    .read = pts_read,
    .write = pts_write,
    .ioctl = pts_ioctl,
};

static void devpts_inode_free(inode_t *self) {
    pty_t *pty = CONTAINER(pty_t, inode, self);

    if (__atomic_exchange_n(&pty->have_inode_ref, false, __ATOMIC_ACQ_REL)) {
        fsdev_deref(&pty->base);
    }
}

static const inode_ops_t devpts_inode_ops = {
    .free = devpts_inode_free,
    .chmodown = deny_chmodown,
    .utime = deny_utime,
};

static inode_t devpts_root_inode;

// kernel addresses always have the high bit set and are thus always above INTPTR_MAX
static uintptr_t *ptys;
static size_t ptys_capacity;
static intptr_t ptys_free = -1;

static void pty_free(fs_device_t *ptr) {
    pty_t *self = (pty_t *)ptr;
    mutex_acq(&devpts_root_inode.lock, 0, false);

    if (!ref_dec(&self->base.references)) {
        mutex_rel(&devpts_root_inode.lock);
        return;
    }

    ptys[self->index] = ptys_free;
    ptys_free = self->index;

    devpts_root_inode.ctime = get_current_timestamp();
    devpts_root_inode.mtime = devpts_root_inode.ctime;

    mutex_rel(&devpts_root_inode.lock);

    ringbuf_free(&self->rx);
    ringbuf_free(&self->tx);
    event_source_cleanup(&self->rx_writable_event);
    event_source_cleanup(&self->tx_readable_event);
    vfree(self, sizeof(*self));
}

static hydrogen_ret_t pty_open(fs_device_t *ptr, inode_t *inode, dentry_t *path, int flags, ident_t *ident) {
    pty_t *pty = (pty_t *)ptr;
    if (__atomic_load_n(&pty->locked, __ATOMIC_ACQUIRE)) return ret_error(EIO);

    pts_file_t *file = vmalloc(sizeof(*file));
    if (unlikely(!file)) return ret_error(ENOMEM);
    memset(file, 0, sizeof(*file));

    init_file(&file->base, &pts_ops, inode, path, flags);

    mutex_acq(&pty->files_lock, 0, false);
    if (!pty->have_master) event_source_signal(&file->disconnect_event);
    list_insert_tail(&pty->files, &file->node);
    mutex_rel(&pty->files_lock);

    mutex_acq(&pty->rx_lock, 0, false);
    if (ringbuf_readable(&pty->rx)) event_source_signal(&file->readable_event);
    mutex_rel(&pty->rx_lock);

    mutex_acq(&pty->tx_lock, 0, false);
    if (ringbuf_writable(&pty->tx)) event_source_signal(&file->writable_event);
    mutex_rel(&pty->tx_lock);

    return ret_pointer(file);
}

static const fs_device_ops_t pty_ops = {
    .free = pty_free,
    .open = pty_open,
};

static hydrogen_ret_t ptmx_open(fs_device_t *self, inode_t *inode, dentry_t *path, int flags, ident_t *ident) {
    static const struct __termios default_settings = {
        .__input_flags = __IUTF8,
        .__output_flags = __OPOST | __ONLCR,
    };

    ptm_file_t *file = vmalloc(sizeof(*file));
    if (unlikely(!file)) return ret_error(ENOMEM);
    memset(file, 0, sizeof(*file));

    pty_t *pty = vmalloc(sizeof(*pty));
    int error = ENOMEM;
    if (unlikely(!pty)) goto err;
    memset(pty, 0, sizeof(*pty));

    pty->base.ops = &pty_ops;
    pty->base.references = REF_INIT(1);

    pty->inode.ops = &devpts_inode_ops;
    pty->inode.fs = devpts_root_inode.fs;
    pty->inode.links = 1;
    pty->inode.atime = get_current_timestamp();
    pty->inode.btime = pty->inode.atime;
    pty->inode.ctime = pty->inode.atime;
    pty->inode.mtime = pty->inode.atime;
    pty->inode.type = HYDROGEN_CHARACTER_DEVICE;
    pty->inode.mode = __S_IRUSR | __S_IWUSR | __S_IWGRP;
    pty->inode.uid = ident->uid;
    pty->inode.gid = ident->gid;
    pty->inode.device = &pty->base;

    pty->locked = true;
    pty->settings = default_settings;

    error = ringbuf_setup(&pty->rx);
    if (unlikely(error)) goto err2;

    error = ringbuf_setup(&pty->tx);
    if (unlikely(error)) goto err3;

    event_source_signal(&pty->rx_writable_event);

    mutex_acq(&devpts_root_inode.lock, 0, false);

    intptr_t index = ptys_free;

    if (index < 0) {
        if (ptys_capacity > INT_MAX) {
            mutex_rel(&devpts_root_inode.lock);
            error = EAGAIN;
            goto err4;
        }

        index = ptys_capacity;

        size_t new_cap = ptys_capacity + 1;
        void *new_ptys = vrealloc(ptys, ptys_capacity * sizeof(*ptys), new_cap * sizeof(*ptys));
        if (unlikely(!new_ptys)) {
            mutex_rel(&devpts_root_inode.lock);
            error = ENOMEM;
            goto err4;
        }
        ptys = new_ptys;
        ptys_capacity = new_cap;
    } else {
        ptys_free = ptys[index];
    }

    ptys[index] = (uintptr_t)pty;

    pty->index = index;
    pty->inode.id = (uint64_t)index + 1;

    devpts_root_inode.ctime = pty->inode.btime;
    devpts_root_inode.mtime = pty->inode.btime;

    mutex_rel(&devpts_root_inode.lock);

    init_file(&file->base, &ptm_ops, inode, path, flags);
    file->pty = pty;

    return ret_pointer(file);
err4:
    ringbuf_free(&pty->tx);
err3:
    ringbuf_free(&pty->rx);
err2:
    vfree(pty, sizeof(*pty));
err:
    vfree(file, sizeof(*file));
    return ret_error(error);
}

static const fs_device_ops_t ptmx_ops = {.open = ptmx_open};
static fs_device_t ptmx_device = {.ops = &ptmx_ops, .references = REF_INIT(1)};

static const fs_ops_t devpts_ops = {};
static filesystem_t devpts_fs = {.ops = &devpts_ops, .block_size = PAGE_SIZE};

static hydrogen_ret_t devpts_root_open(inode_t *self, dentry_t *path, int flags) {
    return ret_error(ENOTSUP);
}

static int devpts_root_lookup(inode_t *self, dentry_t *entry) {
    unsigned index = 0;

    for (size_t i = 0; i < entry->name.size; i++) {
        char c = ((char *)entry->name.data)[i];
        if (unlikely(c < '0' || c > '9')) return ENOENT;
        unsigned new_idx = (index * 10) + (c - '0');
        if (unlikely(new_idx < index)) return ENOENT;
        index = new_idx;
    }

    if (unlikely(index >= ptys_capacity)) return ENOENT;

    uintptr_t value = ptys[index];
    if (unlikely(value <= INTPTR_MAX)) return ENOENT;

    pty_t *pty = (pty_t *)value;
    inode_ref(&pty->inode);

    if (!__atomic_exchange_n(&pty->have_inode_ref, true, __ATOMIC_ACQ_REL)) {
        fsdev_ref(&pty->base);
    }

    entry->inode = &pty->inode;
    return 0;
}

static const inode_ops_t devpts_root_ops = {
    .chmodown = deny_chmodown,
    .utime = deny_utime,
    .directory.open = devpts_root_open,
    .directory.lookup = devpts_root_lookup,
    .directory.create = deny_create,
    .directory.symlink = deny_symlink,
    .directory.link = deny_link,
    .directory.unlink = deny_unlink,
    .directory.rename = deny_rename,
};

static inode_t devpts_root_inode = {
    .ops = &devpts_root_ops,
    .references = REF_INIT(1),
    .fs = &devpts_fs,
    .id = 0,
    .links = 2,
    .type = HYDROGEN_DIRECTORY,
    .mode = 0755,
};

static void create_terminal_devices(void) {
    devpts_fs.id = get_next_fs_id();

    int error = vfs_create(NULL, "/dev/ptmx", 9, HYDROGEN_CHARACTER_DEVICE, 0666, &ptmx_device);
    if (unlikely(error)) panic("failed to create /dev/ptmx (%e)", error);

    error = vfs_create(NULL, "/dev/pts", 8, HYDROGEN_DIRECTORY, 0755, NULL);
    if (unlikely(error)) panic("failed to create /dev/pts (%e)", error);

    error = create_root_dentry(&devpts_fs, &devpts_root_inode);
    if (unlikely(error)) panic("failed to create /dev/pts root dentry (%e)", error);

    error = vfs_mount(NULL, "/dev/pts", 8, &devpts_fs);
    if (unlikely(error)) panic("failed to mount /dev/pts (%e)", error);
}

INIT_DEFINE(create_terminal_devices, create_terminal_devices, INIT_REFERENCE(mount_rootfs));
