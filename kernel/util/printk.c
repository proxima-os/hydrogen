#include "util/printk.h"
#include "arch/irq.h"
#include "kernel/compiler.h"
#include "kernel/types.h"
#include "util/error.h"
#include "util/list.h"
#include "util/spinlock.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static list_t sinks;
static spinlock_t lock;

void printk_add(printk_sink_t *sink) {
    irq_state_t state = printk_lock();
    list_insert_tail(&sinks, &sink->node);
    printk_raw_flush();
    printk_unlock(state);
}

void printk_remove(printk_sink_t *sink) {
    irq_state_t state = printk_lock();
    list_remove(&sinks, &sink->node);
    printk_unlock(state);
}

void vprintk(const char *format, va_list args) {
    irq_state_t state = printk_lock();
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

irq_state_t printk_lock(void) {
    return spin_acq(&lock);
}

void printk_unlock(irq_state_t state) {
    spin_rel(&lock, state);
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

static size_t read_idx;
static size_t write_idx;
static size_t flush_idx;
static bool can_read;
static bool can_flush;

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

    if (can_read && read_idx >= write_idx && (nwi == 0 || read_idx < nwi)) {
        read_idx = nwi;
    }

    write_idx = nwi;
    can_read = true;
    can_flush = true;
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
        read_idx = 0;
        flush_idx = 0;
        can_read = true;
        can_flush = true;
    }
}

void printk_raw_flush(void) {
    flush_to_sinks();
    flush_sinks();
}

size_t printk_raw_read(void *buffer, size_t count) {
    ASSERT(count != 0);

    if (!can_read) return 0;

    size_t max = read_idx < write_idx ? write_idx - read_idx : sizeof(buffer) - read_idx;
    size_t tot = count < max ? count : max;

    memcpy(buffer, &printk_buf[read_idx], tot);
    read_idx += tot;

    if (read_idx == sizeof(buffer)) {
        read_idx = 0;

        count -= tot;
        if (count) {
            buffer += tot;
            max = write_idx;
            size_t cur = count < max ? count : max;

            memcpy(buffer, printk_buf, cur);
            read_idx += cur;
            tot += cur;
        }
    }

    if (read_idx == write_idx) can_read = false;
    return tot;
}
