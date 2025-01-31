#include "util/logging.h"
#include "asm/pio.h"
#include "compiler.h"
#include "string.h"
#include "util/spinlock.h"

#define LOG_BUF_SIZE (1ul << 4)
#define LOG_BUF_MASK (LOG_BUF_SIZE - 1)

static unsigned char klog_buf[LOG_BUF_SIZE];
static size_t flush_idx;
static size_t write_idx;

static spinlock_t klog_lock;

static void flush_data(const void *data, size_t count) {
#if HYDROGEN_QEMU_DEBUGCON
    outsb(0xe9, data, count);
#endif
}

static void do_flush(void) {
    size_t count = write_idx - flush_idx;
    if (unlikely(count == 0)) return;

    if (unlikely(count > LOG_BUF_SIZE)) {
        flush_idx = write_idx - LOG_BUF_SIZE;
        count = LOG_BUF_SIZE;
    }

    size_t offset = flush_idx & LOG_BUF_MASK;
    size_t nfirst = LOG_BUF_SIZE - offset;
    if (nfirst > count) nfirst = count;
    flush_idx = write_idx;

    flush_data(&klog_buf[offset], nfirst);

    if (nfirst != count) {
        flush_data(klog_buf, count - nfirst);
    }
}

static void do_write(const void *data, size_t count) {
    if (unlikely(count > LOG_BUF_SIZE)) {
        data += count - LOG_BUF_SIZE;
        count = LOG_BUF_SIZE;
    }

    size_t offset = write_idx & LOG_BUF_MASK;
    size_t nfirst = LOG_BUF_SIZE - offset;
    if (nfirst > count) nfirst = count;
    write_idx += count;

    memcpy(&klog_buf[offset], data, nfirst);

    if (nfirst != count) {
        memcpy(klog_buf, data + nfirst, count - nfirst);
    }
}

void klog_write(const void *data, size_t count) {
    irq_state_t state = spin_lock(&klog_lock);
    do_write(data, count);
    do_flush();
    spin_unlock(&klog_lock, state);
}

typedef void (*printk_sink_t)(const void *, size_t, void *);

static void print_uint(printk_sink_t sink, void *ctx, uint64_t value, unsigned min_digits, unsigned base) {
    unsigned char buffer[64];
    size_t index = sizeof(buffer);

    do {
        buffer[index] = "0123456789abcdef"[value % base];
        value /= base;
    } while (value > 0);

    size_t count = sizeof(buffer) - index;

    while (index > 0 && count < min_digits) {
        buffer[--index] = '0';
        count += 1;
    }

    sink(&buffer[index], count, ctx);
}

static void print_sint(printk_sink_t sink, void *ctx, int64_t value, unsigned min_digits, unsigned base) {
    if (value < 0) {
        char c = '-';
        sink(&c, sizeof(c), ctx);
        value = -value;
    }

    print_uint(sink, ctx, value, min_digits, base);
}

static void do_printk(printk_sink_t sink, void *ctx, const char *format, va_list args) {
    size_t last = 0;
    size_t i = 0;

    for (;;) {
        char c = format[i];
        if (c == 0) break;

        if (c == '%') {
            if (last != i) {
                sink(format + last, i - last, ctx);
            }

            i += 1;

            unsigned min_digits = 0;
            for (;;) {
                c = format[i++];
                if (c < '0' || c > '9') break;
                min_digits = (min_digits * 10) + (c - '0');
            }

            switch (c) {
            case 'd': print_sint(sink, ctx, va_arg(args, int32_t), min_digits, 10); break;
            case 'u': print_uint(sink, ctx, va_arg(args, uint32_t), min_digits, 10); break;
            case 'x': print_uint(sink, ctx, va_arg(args, uint32_t), min_digits, 16); break;
            case 'D': print_sint(sink, ctx, va_arg(args, int64_t), min_digits, 10); break;
            case 'U': print_uint(sink, ctx, va_arg(args, uint64_t), min_digits, 10); break;
            case 'X': print_uint(sink, ctx, va_arg(args, uint64_t), min_digits, 16); break;
            case 'p': {
                static const char prefix[2] = "0x";
                sink(prefix, sizeof(prefix), ctx);
                print_uint(sink, ctx, (uintptr_t)va_arg(args, void *), 0, 16);
                break;
            }
            case '%': {
                char c = '%';
                sink(&c, sizeof(c), ctx);
                break;
            }
            case 'c': {
                char c = va_arg(args, int);
                sink(&c, sizeof(c), ctx);
                break;
            }
            case 's': {
                static const char def[6] = "(null)";
                const char *s = va_arg(args, const char *);
                if (s) sink(s, strlen(s), ctx);
                else sink(def, sizeof(def), ctx);
                break;
            }
            case 'S': {
                const void *ptr = va_arg(args, const void *);
                size_t count = va_arg(args, size_t);
                sink(ptr, count, ctx);
                break;
            }
            }

            last = i;
        } else {
            i += 1;
        }
    }

    if (last != i) {
        sink(format + last, i - last, ctx);
    }
}

static void klog_sink(const void *data, size_t count, UNUSED void *ctx) {
    do_write(data, count);
}

void vprintk(const char *format, va_list args) {
    irq_state_t state = spin_lock(&klog_lock);
    do_printk(klog_sink, NULL, format, args);
    do_flush();
    spin_unlock(&klog_lock, state);
}

void printk(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintk(format, args);
    va_end(args);
}

struct snprintk_ctx {
    void *buffer;
    size_t count;
    size_t total;
};

static void snprintk_sink(const void *data, size_t count, void *ptr) {
    struct snprintk_ctx *ctx = ptr;
    ctx->total += count;

    if (count > ctx->count) {
        count = ctx->count;
    }

    memcpy(ctx->buffer, data, count);
    ctx->count += count;
}

size_t vsnprintk(void *buffer, size_t size, const char *format, va_list args) {
    struct snprintk_ctx ctx = {buffer, size, 0};
    do_printk(snprintk_sink, &ctx, format, args);
    return ctx.total;
}

size_t snprintk(void *buffer, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    size_t n = vsnprintk(buffer, size, format, args);
    va_end(args);
    return n;
}
