#include "util/printk.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "fs/vfs.h"
#include "hydrogen/filesystem.h"
#include "hydrogen/types.h"
#include "init/main.h" /* IWYU pragma: keep */
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "kernel/types.h"
#include "mem/vmalloc.h"
#include "proc/sched.h"
#include "util/error.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/spinlock.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static list_t sinks;
static spinlock_t lock;

void printk_add(printk_sink_t *sink) {
    printk_state_t state = printk_lock();
    list_insert_tail(&sinks, &sink->node);
    printk_raw_flush();
    printk_unlock(state);
}

void printk_remove(printk_sink_t *sink) {
    printk_state_t state = printk_lock();
    list_remove(&sinks, &sink->node);
    printk_unlock(state);
}

void vprintk(const char *format, va_list args) {
    printk_state_t state = printk_lock();
    printk_raw_formatv(format, args);
    printk_raw_flush();
    printk_unlock(state);
}

void printk(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintk(format, args);
    va_end(args);
}

printk_state_t printk_lock(void) {
    printk_state_t state = {};
    state.preempt = preempt_lock();
    state.irq = spin_acq(&lock);
    return state;
}

void printk_unlock(printk_state_t state) {
    spin_rel(&lock, state.irq);
    preempt_unlock(state.preempt);
}

static void write_uint(uint64_t value, unsigned base, unsigned min_digits, bool alternate) {
    unsigned char buf[32];
    size_t index = sizeof(buf);

    do {
        buf[--index] = "0123456789abcdef"[value % base];
        value /= base;
    } while (index > 0 && value > 0);

    while (index > 0 && sizeof(buf) - index < min_digits) buf[--index] = '0';

    if (alternate) {
        if (base == 16) {
            if (index < 2) index = 2;
            buf[--index] = 'x';
            buf[--index] = '0';
        } else if (base == 8) {
            if (buf[index] != '0') {
                if (index < 1) index = 1;
                buf[--index] = '0';
            }
        } else {
            buf[index ? --index : 0] = '-';
        }
    }

    printk_raw_write(&buf[index], sizeof(buf) - index);
}

static void write_int(int64_t value, unsigned base, unsigned min_digits) {
    if (value >= 0) {
        write_uint(value, base, min_digits, false);
    } else {
        write_uint(-(uint64_t)value, base, min_digits, true);
    }
}

void printk_raw_formatv(const char *format, va_list args) {
    const char *last = format;

    for (;;) {
        char c = *format;
        if (!c) break;
        if (c != '%') {
            format++;
            continue;
        }

        if (last != format) {
            printk_raw_write(last, format - last);
            last = format;
        }

        int min_digits = 0;

        for (;;) {
            c = *++format;
            if (c < '0' || c > '9') break;
            min_digits = (min_digits * 10) + (c - '0');
        }

        format++;
        switch (c) {
        case 'c':
            c = va_arg(args, int);
            printk_raw_write(&c, 1);
            break;
        case 's': {
            char *s = va_arg(args, char *);
            if (!s) s = "(null)";
            printk_raw_write(s, strlen(s));
            break;
        }
        case 'S': {
            void *ptr = va_arg(args, void *);
            size_t len = va_arg(args, size_t);
            printk_raw_write(ptr, len);
            break;
        }
        case 'o': write_uint(va_arg(args, uint32_t), 8, min_digits, true); break;
        case 'O': write_uint(va_arg(args, uint64_t), 8, min_digits, true); break;
        case 'd': write_int(va_arg(args, int32_t), 10, min_digits); break;
        case 'D': write_int(va_arg(args, int64_t), 10, min_digits); break;
        case 'u': write_uint(va_arg(args, uint32_t), 10, min_digits, false); break;
        case 'U': write_uint(va_arg(args, uint64_t), 10, min_digits, false); break;
        case 'x': write_uint(va_arg(args, uint32_t), 16, min_digits, false); break;
        case 'X': write_uint(va_arg(args, uint64_t), 16, min_digits, false); break;
        case 'q': write_int(va_arg(args, ssize_t), 10, min_digits); break;
        case 'z': write_uint(va_arg(args, size_t), 10, min_digits, false); break;
        case 'Z': write_uint(va_arg(args, size_t), 16, min_digits, false); break;
        case 'p': write_uint((uintptr_t)va_arg(args, void *), 16, min_digits, true); break;
        case '%': printk_raw_write(&c, 1); break;
        case 'e': {
            const char *s = error_to_string(va_arg(args, int));
            printk_raw_write(s, strlen(s));
            break;
        }
        default: goto next;
        }
        last = format;
    next:
        continue;
    }

    if (last != format) {
        printk_raw_write(last, format - last);
    }
}

void printk_raw_format(const char *format, ...) {
    va_list args;
    va_start(args, format);
    printk_raw_formatv(format, args);
    va_end(args);
}

static void write_to_sinks(const void *data, size_t count) {
    LIST_FOREACH(sinks, printk_sink_t, node, sink) {
        sink->write(sink, data, count);
    }
}

static void flush_sinks(void) {
    LIST_FOREACH(sinks, printk_sink_t, node, sink) {
        if (sink->flush) sink->flush(sink);
    }
}

static unsigned char printk_buf[1ul << HYDROGEN_LOG_BUF_SHIFT];

typedef struct {
    file_t base;
    list_node_t node;
    size_t read_idx;
    bool can_read;
} klog_file_t;

static list_t klog_readers;
static list_t klog_waiting;
static size_t write_idx;
static size_t flush_idx;
static bool can_flush;
static bool can_read_init;

static void flush_to_sinks(void) {
    if (!can_flush || list_empty(&sinks)) return;

    if (flush_idx < write_idx) {
        write_to_sinks(&printk_buf[flush_idx], write_idx - flush_idx);
    } else {
        write_to_sinks(&printk_buf[flush_idx], sizeof(printk_buf) - flush_idx);

        if (write_idx != 0) {
            write_to_sinks(printk_buf, write_idx);
        }
    }

    flush_idx = write_idx;
    can_flush = false;
}

static void wake_readers(void) {
    thread_t *thread = LIST_HEAD(klog_waiting, thread_t, wait_node);

    while (thread) {
        thread_t *next = LIST_NEXT(*thread, thread_t, wait_node);

        if (sched_wake(thread)) {
            list_remove(&klog_waiting, &thread->wait_node);
        }

        thread = next;
    }
}

static size_t write_single(const void *data, size_t count) {
    size_t cur = sizeof(printk_buf) - write_idx;
    if (cur > count) cur = count;
    size_t nwi = write_idx + cur;

    if (can_flush && flush_idx >= write_idx && flush_idx < nwi) {
        write_to_sinks(&printk_buf[flush_idx], nwi - flush_idx);
        if (nwi == sizeof(printk_buf)) nwi = 0;
        flush_idx = nwi;
    } else if (nwi == sizeof(printk_buf)) {
        nwi = 0;
    }

    memcpy(&printk_buf[write_idx], data, cur);

    LIST_FOREACH(klog_readers, klog_file_t, node, reader) {
        if (reader->can_read && reader->read_idx >= write_idx && (nwi == 0 || reader->can_read < nwi)) {
            reader->read_idx = nwi;
        }

        reader->can_read = true;
    }

    write_idx = nwi;
    can_flush = true;
    can_read_init = true;
    wake_readers();

    return cur;
}

void printk_raw_write(const void *data, size_t count) {
    ASSERT(count != 0);

    if (count < sizeof(printk_buf)) {
        size_t cur = write_single(data, count);
        count -= cur;

        if (count != 0) {
            data += cur;
            count -= write_single(data, count);
            ASSERT(count == 0);
        }
    } else {
        flush_to_sinks();

        size_t diff = count - sizeof(printk_buf);
        if (diff) write_to_sinks(data, diff);
        data += diff;

        memcpy(printk_buf, data, sizeof(printk_buf));
        write_idx = 0;
        flush_idx = 0;
        can_flush = true;

        LIST_FOREACH(klog_readers, klog_file_t, node, reader) {
            reader->read_idx = 0;
            reader->can_read = true;
        }

        can_read_init = true;
        wake_readers();
    }
}

void printk_raw_flush(void) {
    flush_to_sinks();
    flush_sinks();
}

static void klog_file_free(object_t *ptr) {
    klog_file_t *self = (klog_file_t *)ptr;

    if (self->base.flags & __O_RDONLY) {
        printk_state_t state = printk_lock();
        list_remove(&klog_readers, &self->node);
        printk_unlock(state);
    }

    vfree(self, sizeof(*self));
}

static hydrogen_ret_t klog_file_read(file_t *ptr, void *buffer, size_t size, uint64_t position) {
    klog_file_t *self = (klog_file_t *)ptr;
    printk_state_t state = printk_lock();

    while (!self->can_read) {
        if (self->base.flags & __O_NONBLOCK) {
            printk_unlock(state);
            return ret_error(EAGAIN);
        }

        list_insert_tail(&klog_waiting, &current_thread->wait_node);
        sched_prepare_wait(true);
        printk_unlock(state);
        int error = sched_perform_wait(0);
        printk_lock();

        if (unlikely(error)) {
            list_remove(&klog_waiting, &current_thread->wait_node);
            printk_unlock(state);
            return ret_error(error);
        }
    }

    size_t tot = 0;

    do {
        size_t max = self->read_idx < write_idx ? write_idx - self->read_idx : sizeof(printk_buf) - self->read_idx;
        size_t cur = size < max ? size : max;

        void *ptr = &printk_buf[self->read_idx];

        self->read_idx += cur;
        if (self->read_idx == sizeof(printk_buf)) self->read_idx = 0;
        if (self->read_idx == write_idx) self->can_read = false;

        printk_unlock(state);

        int error = user_memcpy(buffer + tot, ptr, cur);
        if (unlikely(error)) return ret_error(error);
        tot += cur;
        if (tot == size) return ret_integer(tot);

        state = printk_lock();
    } while (self->can_read);

    printk_unlock(state);
    return ret_integer(tot);
}

#define BUFFER_SIZE 1024

static hydrogen_ret_t klog_file_write(file_t *ptr, const void *buffer, size_t size, uint64_t position, bool rpos) {
    unsigned char buf[BUFFER_SIZE];
    size_t total = 0;

    do {
        size_t cur = sizeof(buf) < size ? sizeof(buf) : size;
        int error = user_memcpy(buf, buffer + total, cur);
        if (unlikely(error)) return ret_error(error);

        printk_state_t state = printk_lock();
        printk_raw_write(buf, cur);
        printk_raw_flush();
        printk_unlock(state);

        total += cur;
    } while (total < size);

    return ret_integer(total);
}

static const file_ops_t klog_file_ops = {
        .base.free = klog_file_free,
        .read = klog_file_read,
        .write = klog_file_write,
};

static hydrogen_ret_t klog_open(fs_device_t *ptr, inode_t *inode, dentry_t *path, int flags) {
    klog_file_t *file = vmalloc(sizeof(*file));
    if (unlikely(!file)) return ret_error(ENOMEM);

    init_file(&file->base, &klog_file_ops, inode, path, flags);

    if (flags & __O_RDONLY) {
        printk_state_t state = printk_lock();

        file->can_read = can_read_init;
        list_insert_tail(&klog_readers, &file->node);

        printk_unlock(state);
    }

    return ret_pointer(&file->base);
}

static const fs_device_ops_t klog_device_ops = {
        .open = klog_open,
};

static void create_klog_device(void) {
    static fs_device_t device = {.ops = &klog_device_ops};

    int error = vfs_create(NULL, "/dev/klog", 9, HYDROGEN_CHARACTER_DEVICE, 0600, &device);
    if (unlikely(error)) panic("failed to create /dev/klog (%e)", error);
}

INIT_DEFINE(create_klog_device, create_klog_device, INIT_REFERENCE(mount_rootfs));
