#include "util/print.h"
#include "asm/irq.h"
#include "proxima/compiler.h"
#include "fs/vfs.h"
#include "hydrogen/error.h"
#include "hydrogen/fcntl.h"
#include "limine.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "mem/pmm.h"
#include "mem/vheap.h"
#include "string.h"
#include "sys/syscall.h"
#include "util/panic.h"
#include "util/spinlock.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

// This is a very basic framebuffer printing implementation - it doesn't even implement scrolling, just wraparound,
// and makes no attempt at minimizing the number of drawn characters. That's because it's only meant to be used during
// boot and for panics. The terminal used by userspace will be implemented *in* userspace as a pseudoterminal that draws
// directly to the framebuffer.

#define CHAR_WIDTH 8
#define CHAR_HEIGHT 16
#define MAX_DIGITS 32

static volatile void *framebuffer;
static uint64_t fb_width;
static uint64_t fb_height;
static uint64_t fb_pitch;
static uint64_t term_width;
static uint64_t term_height;
static uint64_t term_pitch;
static uint64_t term_x;
static uint64_t term_y;
static spinlock_t term_lock;

static const unsigned char font[CHAR_HEIGHT * 256];

void init_print(void) {
    LIMINE_REQ static struct limine_framebuffer_request fb_req = {.id = LIMINE_FRAMEBUFFER_REQUEST};
    if (!fb_req.response) return;

    for (uint64_t i = 0; i < fb_req.response->framebuffer_count; i++) {
        struct limine_framebuffer *fb = fb_req.response->framebuffers[i];

        if (fb->memory_model != LIMINE_FRAMEBUFFER_RGB) continue;
        if (fb->bpp != 32) continue;
        if ((uintptr_t)fb->address & (_Alignof(uint32_t) - 1)) continue;

        uint64_t cur_width = fb->width / CHAR_WIDTH;
        uint64_t cur_height = fb->height / CHAR_HEIGHT;

        if (cur_width * cur_height > term_width * term_height) {
            framebuffer = fb->address;
            fb_width = fb->width;
            fb_height = fb->height;
            fb_pitch = fb->pitch;
            term_width = cur_width;
            term_height = cur_height;
            term_pitch = fb_pitch * CHAR_HEIGHT;
        }
    }
}

void map_print(void) {
    if (framebuffer) {
        uintptr_t addr;
        int error = kvmm_map_mmio(
                &addr,
                (uintptr_t)framebuffer - (uintptr_t)hhdm_start,
                fb_pitch * fb_height,
                PMAP_WRITE,
                CACHE_WRITE_COMBINE
        );
        if (error) panic("failed to map framebuffer (%d)", error);
        framebuffer = (volatile void *)addr;
    }
}

static void draw_char(unsigned char c, uint64_t x, uint64_t y) {
    volatile void *fb_ptr = framebuffer + y * term_pitch + x * CHAR_WIDTH * 4;
    const unsigned char *bitmap = &font[c * CHAR_HEIGHT];

    for (int i = 0; i < CHAR_HEIGHT; i++) {
        volatile uint32_t *line_ptr = fb_ptr;
        unsigned char line_map = *bitmap;

        for (int j = 0; j < CHAR_WIDTH; j++) {
            line_ptr[j] = line_map & (1 << (CHAR_WIDTH - 1)) ? UINT32_MAX : 0;
            line_map <<= 1;
        }

        fb_ptr += fb_pitch;
        bitmap += 1;
    }
}

static void print_char(unsigned char c, UNUSED void *ctx) {
    uint32_t start_y = term_y;

    switch (c) {
    case '\n': term_y += 1; // fall through
    case '\r': term_x = 0; break;
    default: draw_char(c, term_x++, term_y); break;
    }

    if (term_x >= term_width) {
        term_x = 0;
        term_y += 1;
    }

    if (term_y >= term_height) {
        term_y = 0; // no scrolling, just wraparound
    }

    if (term_y != start_y) {
        for (uint32_t x = 0; x < term_width; x++) {
            draw_char(' ', x, term_y);
        }
    }
}

static void kcon_free(file_t *self) {
    vmfree(self, sizeof(*self));
}

static int kcon_write(UNUSED file_t *self, const void *buffer, size_t *size) {
    unsigned char buf[128];
    size_t n = *size;

    while (n > 0) {
        size_t cur = n < sizeof(buf) ? n : sizeof(buf);
        int error = memcpy_user(buf, buffer, n);
        if (unlikely(error)) return error;

        irq_state_t state = spin_lock(&term_lock);

        for (size_t i = 0; i < cur; i++) {
            print_char(buf[i], NULL);
        }

        spin_unlock(&term_lock, state);

        buffer += cur;
        n -= cur;
    }

    return 0;
}

static const file_ops_t kcon_ops = {.free = kcon_free, .write = kcon_write};

int create_kcon_handle(file_t **out) {
    file_t *file = vmalloc(sizeof(*file));
    if (unlikely(!file)) return ERR_OUT_OF_MEMORY;
    memset(file, 0, sizeof(*file));

    file->ops = &kcon_ops;
    file->references = 1;
    file->mode = O_WRONLY;

    *out = file;
    return 0;
}

typedef void (*printk_func_t)(unsigned char, void *);

static void print_str(const char *s, printk_func_t func, void *ctx) {
    if (!s) s = "(null)";

    for (char c = *s; c != 0; c = *++s) {
        func(c, ctx);
    }
}

static void print_tstr(const unsigned char *s, size_t count, printk_func_t func, void *ctx) {
    for (size_t i = 0; i < count; i++) {
        func(s[i], ctx);
    }
}

static void print_uint(uint64_t value, unsigned base, unsigned min_digits, printk_func_t func, void *ctx) {
    unsigned char buffer[MAX_DIGITS];
    size_t pos = sizeof(buffer);

    do {
        buffer[--pos] = "0123456789abcdef"[value % base];
        value /= base;
    } while (pos > 0 && value > 0);

    while (pos > 0 && sizeof(buffer) - pos < min_digits) {
        buffer[--pos] = '0';
    }

    print_tstr(&buffer[pos], sizeof(buffer) - pos, func, ctx);
}

static void print_sint(int64_t value, unsigned base, unsigned min_digits, printk_func_t func, void *ctx) {
    if (value < 0) {
        value = -value;
        func('-', ctx);
    }

    print_uint(value, base, min_digits, func, ctx);
}

static void do_vprintk(const char *format, va_list args, printk_func_t func, void *ctx) {
    for (char c = *format; c != 0; c = *++format) {
        if (c == '%') {
            unsigned min_digits = 0;

            for (;;) {
                char c = format[1];
                if (c < '0' || c > '9') break;
                min_digits = (min_digits * 10) + (c - '0');
                format++;
            }

            switch (*++format) {
            case 0: format--; break;
            case '%': func('%', ctx); break;
            case 'c': func(va_arg(args, int), ctx); break;
            case 's': print_str(va_arg(args, const char *), func, ctx); break;
            case 'S': {
                const void *ptr = va_arg(args, const void *);
                size_t count = va_arg(args, size_t);
                print_tstr(ptr, count, func, ctx);
                break;
            }
            case 'p': {
                const void *ptr = va_arg(args, const void *);

                if (ptr != NULL) {
                    print_str("0x", func, ctx);
                    print_uint((uintptr_t)ptr, 16, 0, func, ctx);
                } else {
                    print_str("NULL", func, ctx);
                }
                break;
            }
            case 'd': print_sint(va_arg(args, int32_t), 10, min_digits, func, ctx); break;
            case 'u': print_uint(va_arg(args, uint32_t), 10, min_digits, func, ctx); break;
            case 'x': print_uint(va_arg(args, uint32_t), 16, min_digits, func, ctx); break;
            case 'D': print_sint(va_arg(args, int64_t), 10, min_digits, func, ctx); break;
            case 'U': print_uint(va_arg(args, uint64_t), 10, min_digits, func, ctx); break;
            case 'X': print_uint(va_arg(args, uint64_t), 16, min_digits, func, ctx); break;
            }
        } else {
            func(c, ctx);
        }
    }
}

void vprintk(const char *format, va_list args) {
    if (!framebuffer) return;

    irq_state_t state = spin_lock(&term_lock);
    do_vprintk(format, args, print_char, NULL);
    spin_unlock(&term_lock, state);
}

void printk(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintk(format, args);
    va_end(args);
}

struct vsnprintk_ctx {
    unsigned char *buf;
    size_t rem;
    size_t tot;
};

static void add_char(unsigned char c, void *ptr) {
    struct vsnprintk_ctx *ctx = ptr;

    if (ctx->rem != 0) {
        *(ctx->buf++) = c;
        ctx->rem -= 1;
    }

    ctx->tot += 1;
}

size_t vsnprintk(void *buf, size_t size, const char *format, va_list args) {
    struct vsnprintk_ctx ctx = {buf, size, 0};
    do_vprintk(format, args, add_char, &ctx);
    return ctx.tot;
}

size_t snprintk(void *buf, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    size_t count = vsnprintk(buf, size, format, args);
    va_end(args);
    return count;
}

// From
// https://github.com/viler-int10h/vga-text-mode-fonts/blob/f6a9b77d850ccf3d642331da54442d89f79ef9e3/FONTS/PC-OTHER/TOSH-SAT.F16
static const unsigned char font[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c,
        0x42, 0x81, 0x81, 0xa5, 0xa5, 0x81, 0x81, 0xa5, 0x99, 0x81, 0x42, 0x3c, 0x00, 0x00, 0x00, 0x3c, 0x7e, 0xff,
        0xff, 0xdb, 0xdb, 0xff, 0xff, 0xdb, 0xe7, 0xff, 0x7e, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0xfe, 0xfe,
        0xfe, 0x7c, 0x7c, 0x38, 0x38, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10, 0x38, 0x38, 0x7c, 0x7c, 0xfe,
        0x7c, 0x7c, 0x38, 0x38, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x3c, 0x3c, 0xdb, 0xff, 0xff, 0xdb,
        0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x3c, 0x7e, 0xff, 0xff, 0xff, 0x66, 0x18, 0x18,
        0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x78, 0x78, 0x30, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe7, 0xc3, 0xc3, 0xe7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0xcc, 0x84, 0x84, 0xcc, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xc3, 0x99, 0xbd, 0xbd, 0x99, 0xc3, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x1e,
        0x0e, 0x1e, 0x32, 0x78, 0xcc, 0xcc, 0xcc, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0xcc, 0xcc,
        0xcc, 0x78, 0x30, 0xfc, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x18, 0x1c, 0x1e, 0x16, 0x12,
        0x10, 0x10, 0x70, 0xf0, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x30, 0x38, 0x2c, 0x26, 0x32, 0x3a, 0x2e, 0x26, 0x22,
        0x62, 0xe2, 0xc6, 0x0e, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0xdb, 0x3c, 0xe7, 0x3c, 0xdb, 0x18, 0x18,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xc0, 0xe0, 0xf8, 0xfe, 0xf8, 0xe0, 0xc0, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x06, 0x0e, 0x3e, 0xfe, 0x3e, 0x0e, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x30, 0x78, 0xfc, 0x30, 0x30, 0x30, 0x30, 0x30, 0xfc, 0x78, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x00, 0xcc, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xdb,
        0xdb, 0xdb, 0xdb, 0x7b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0x60, 0x38,
        0x6c, 0xc6, 0xc6, 0x6c, 0x38, 0x0c, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xfe, 0xfe, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x78, 0xfc, 0x30, 0x30, 0x30, 0x30, 0x30,
        0xfc, 0x78, 0x30, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x30, 0x78, 0xfc, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0xfc, 0x78, 0x30, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x0c, 0xfe, 0xfe, 0x0c, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x60, 0xfe, 0xfe, 0x60, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xc0, 0xc0, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x24, 0x66, 0xff, 0xff, 0x66, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10,
        0x38, 0x38, 0x7c, 0x7c, 0xfe, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xfe, 0x7c, 0x7c,
        0x38, 0x38, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x78, 0x78, 0x78, 0x78, 0x30, 0x30, 0x30, 0x00, 0x30,
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x6c, 0x6c, 0x6c, 0xfe, 0x6c, 0x6c, 0x6c, 0xfe, 0x6c, 0x6c, 0x6c, 0x00, 0x00, 0x00,
        0x00, 0x18, 0x18, 0x7c, 0xc6, 0xc0, 0xc0, 0x7c, 0x06, 0x06, 0xc6, 0x7c, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00,
        0xc6, 0xc6, 0x0c, 0x0c, 0x18, 0x38, 0x30, 0x60, 0x60, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x6c,
        0x6c, 0x38, 0x30, 0x76, 0xde, 0xcc, 0xcc, 0xde, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x18, 0x30,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x30, 0x60, 0x60, 0x60, 0x60,
        0x60, 0x60, 0x60, 0x30, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x30, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
        0x18, 0x30, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x38, 0xfe, 0x38, 0x6c, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x7e, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x06,
        0x0c, 0x0c, 0x18, 0x38, 0x30, 0x60, 0x60, 0xc0, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xc6, 0xc6,
        0xd6, 0xd6, 0xd6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x38, 0x78, 0x18, 0x18, 0x18,
        0x18, 0x18, 0x18, 0x18, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0x06, 0x06, 0x0c, 0x18, 0x30, 0x60,
        0xc0, 0xc0, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0x06, 0x06, 0x3c, 0x06, 0x06, 0x06, 0x06, 0xc6,
        0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x0c, 0x1c, 0x3c, 0x6c, 0xcc, 0xfe, 0x0c, 0x0c, 0x0c, 0x0c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xfe, 0xc0, 0xc0, 0xc0, 0xfc, 0x06, 0x06, 0x06, 0x06, 0xc6, 0x7c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x3c, 0x60, 0xc0, 0xc0, 0xfc, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xfe, 0xc6, 0x06, 0x06, 0x0c, 0x18, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6,
        0xc6, 0xc6, 0x7c, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xc6, 0xc6,
        0xc6, 0x7e, 0x06, 0x06, 0x06, 0x0c, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
        0x18, 0x00, 0x00, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00,
        0x00, 0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0, 0x60, 0x30, 0x18, 0x0c,
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xc0, 0x60, 0x30, 0x18, 0x0c, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x7c, 0xc6, 0xc6, 0x06, 0x0c, 0x18, 0x30, 0x30, 0x00, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7c, 0xc6, 0xc6, 0xc6, 0xde, 0xde, 0xde, 0xde, 0xc0, 0xc0, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x6c,
        0xc6, 0xc6, 0xc6, 0xc6, 0xfe, 0xc6, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xc6, 0xc6, 0xc6,
        0xfc, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xc0, 0xc0, 0xc0, 0xc0,
        0xc0, 0xc0, 0xc0, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xcc, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
        0xc6, 0xcc, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xc0, 0xc0, 0xc0, 0xfc, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0,
        0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xc0, 0xc0, 0xc0, 0xfc, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xc0, 0xc0, 0xc0, 0xde, 0xc6, 0xc6, 0xc6, 0xc6, 0x7e, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xfe, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xfc, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x0c,
        0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0xcc, 0xcc, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0xc6, 0xcc, 0xd8,
        0xf0, 0xe0, 0xf0, 0xd8, 0xcc, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0,
        0xc0, 0xc0, 0xc0, 0xc0, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0xc6, 0xee, 0xfe, 0xd6, 0xd6, 0xd6, 0xc6,
        0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0xc6, 0xe6, 0xe6, 0xf6, 0xde, 0xce, 0xce, 0xc6, 0xc6,
        0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xfc, 0xc6, 0xc6, 0xc6, 0xc6, 0xfc, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x7c, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xf6, 0xda, 0x6c, 0x06, 0x00, 0x00, 0x00, 0x00,
        0xfc, 0xc6, 0xc6, 0xc6, 0xc6, 0xfc, 0xd8, 0xcc, 0xcc, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6,
        0xc0, 0x60, 0x30, 0x18, 0x0c, 0x06, 0x06, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x18, 0x18, 0x18,
        0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
        0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
        0x6c, 0x38, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xd6, 0xd6, 0xd6, 0xd6, 0xfe, 0x6c,
        0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0xc6, 0xc6, 0x6c, 0x38, 0x38, 0x38, 0x6c, 0xc6, 0xc6, 0xc6, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x78, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xfe, 0x06, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0, 0xc0, 0xc0, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x78, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xc0,
        0x60, 0x60, 0x30, 0x38, 0x18, 0x0c, 0x0c, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x18, 0x18, 0x18,
        0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x38, 0x6c, 0xc6, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x18, 0x18, 0x18, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x06, 0x06, 0x7e, 0xc6, 0xc6, 0xc6, 0x7e, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xc0, 0xc0, 0xc0, 0xdc, 0xe6, 0xc6, 0xc6, 0xc6, 0xc6, 0xe6, 0xdc, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xc0, 0xc0, 0xc0, 0xc0, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x06, 0x06, 0x76, 0xce, 0xc6, 0xc6, 0xc6, 0xc6, 0xce, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x7c, 0xc6, 0xc6, 0xfe, 0xc0, 0xc0, 0xc0, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x36, 0x30, 0x30,
        0xfc, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xce, 0xc6,
        0xc6, 0xc6, 0xce, 0x76, 0x06, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0xc0, 0xc0, 0xc0, 0xdc, 0xe6, 0xc6, 0xc6, 0xc6,
        0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
        0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x1e, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0xc6, 0xc6,
        0x7c, 0x00, 0x00, 0x00, 0xc0, 0xc0, 0xc0, 0xc6, 0xcc, 0xd8, 0xf0, 0xf0, 0xd8, 0xcc, 0xc6, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xec, 0xfe, 0xd6, 0xd6, 0xd6, 0xd6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xdc, 0xe6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c,
        0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdc, 0xe6, 0xc6,
        0xc6, 0xc6, 0xe6, 0xdc, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xce, 0xc6, 0xc6, 0xc6,
        0xce, 0x76, 0x06, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdc, 0xe6, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0,
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xc0, 0x70, 0x1c, 0x06, 0xc6, 0x7c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x30, 0xfe, 0x30, 0x30, 0x30, 0x30, 0x30, 0x36, 0x1c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x6c, 0x38, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xc6, 0xc6, 0xd6, 0xd6, 0xd6, 0xd6, 0xfe, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6,
        0xc6, 0x6c, 0x38, 0x38, 0x6c, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0xc6, 0xc6,
        0xc6, 0xc6, 0xce, 0x76, 0x06, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x06, 0x0c, 0x18, 0x30,
        0x60, 0xc0, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x30, 0x30, 0x30, 0x30, 0xe0, 0x30, 0x30, 0x30, 0x30,
        0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xe0, 0x30, 0x30, 0x30, 0x30, 0x1c, 0x30, 0x30, 0x30, 0x30, 0xe0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x76, 0xdc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x10, 0x38, 0x38, 0x6c, 0x6c, 0xc6, 0xc6, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x66,
        0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0x66, 0x3c, 0x18, 0xcc, 0x78, 0x00, 0x00, 0x00, 0x6c, 0x6c, 0x00, 0xc6,
        0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x18, 0x30, 0x00, 0x7c, 0xc6, 0xc6,
        0xfe, 0xc0, 0xc0, 0xc0, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x10, 0x38, 0x6c, 0x00, 0x7c, 0x06, 0x06, 0x7e, 0xc6,
        0xc6, 0xc6, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x6c, 0x00, 0x7c, 0x06, 0x06, 0x7e, 0xc6, 0xc6, 0xc6,
        0x7e, 0x00, 0x00, 0x00, 0x00, 0x60, 0x30, 0x18, 0x00, 0x7c, 0x06, 0x06, 0x7e, 0xc6, 0xc6, 0xc6, 0x7e, 0x00,
        0x00, 0x00, 0x00, 0x38, 0x6c, 0x38, 0x00, 0x7c, 0x06, 0x06, 0x7e, 0xc6, 0xc6, 0xc6, 0x7e, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0xc6, 0xc0, 0xc0, 0xc0, 0xc0, 0xc6, 0x7c, 0x18, 0x0c, 0x38, 0x00, 0x10,
        0x38, 0x6c, 0x00, 0x7c, 0xc6, 0xc6, 0xfe, 0xc0, 0xc0, 0xc0, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x6c,
        0x00, 0x7c, 0xc6, 0xc6, 0xfe, 0xc0, 0xc0, 0xc0, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x60, 0x30, 0x18, 0x00, 0x7c,
        0xc6, 0xc6, 0xfe, 0xc0, 0xc0, 0xc0, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x6c, 0x00, 0x38, 0x18, 0x18,
        0x18, 0x18, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x10, 0x38, 0x6c, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18,
        0x18, 0x18, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x60, 0x30, 0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
        0x3c, 0x00, 0x00, 0x00, 0xc6, 0xc6, 0x10, 0x38, 0x6c, 0xc6, 0xc6, 0xc6, 0xfe, 0xc6, 0xc6, 0xc6, 0xc6, 0x00,
        0x00, 0x00, 0x38, 0x6c, 0x38, 0x00, 0x38, 0x6c, 0xc6, 0xc6, 0xc6, 0xfe, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00,
        0x18, 0x30, 0x60, 0x00, 0xfe, 0xc0, 0xc0, 0xfc, 0xc0, 0xc0, 0xc0, 0xc0, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xec, 0x36, 0x36, 0x76, 0xde, 0xd8, 0xd8, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x3c,
        0x6c, 0xcc, 0xcc, 0xfe, 0xcc, 0xcc, 0xcc, 0xcc, 0xce, 0x00, 0x00, 0x00, 0x00, 0x10, 0x38, 0x6c, 0x00, 0x7c,
        0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x6c, 0x00, 0x7c, 0xc6, 0xc6,
        0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x60, 0x30, 0x18, 0x00, 0x7c, 0xc6, 0xc6, 0xc6, 0xc6,
        0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x10, 0x38, 0x6c, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
        0x7c, 0x00, 0x00, 0x00, 0x00, 0x60, 0x30, 0x18, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x6c, 0x6c, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xce, 0x76, 0x06, 0xc6, 0x7c, 0x00,
        0x6c, 0x6c, 0x00, 0x7c, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x6c, 0x6c,
        0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
        0x30, 0x78, 0xcc, 0xc0, 0xc0, 0xcc, 0x78, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x6c, 0x60, 0x60,
        0x60, 0xf8, 0x60, 0x60, 0x60, 0xe6, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc, 0x78, 0x30, 0xfc,
        0x30, 0xfc, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xcc, 0xcc, 0xf8, 0xc4, 0xcc, 0xde, 0xcc,
        0xcc, 0xcc, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x1b, 0x18, 0x18, 0x18, 0x7e, 0x18, 0x18, 0x18, 0x18,
        0x18, 0xd8, 0x70, 0x00, 0x00, 0x0c, 0x18, 0x30, 0x00, 0x7c, 0x06, 0x06, 0x7e, 0xc6, 0xc6, 0xc6, 0x7e, 0x00,
        0x00, 0x00, 0x00, 0x0c, 0x18, 0x30, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3c, 0x00, 0x00, 0x00,
        0x00, 0x0c, 0x18, 0x30, 0x00, 0x7c, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x0c,
        0x18, 0x30, 0x00, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x76, 0xdc, 0x00,
        0x00, 0xdc, 0xe6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x76, 0xdc, 0x00, 0xc6, 0xc6, 0xe6,
        0xf6, 0xfe, 0xde, 0xce, 0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x78, 0xd8, 0xd8, 0x6c, 0x00, 0xfc, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x6c, 0x6c, 0x38, 0x00, 0x7c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x30, 0x60, 0xc0, 0xc6, 0xc6,
        0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xc0, 0xc0, 0xc0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x06, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xc0, 0xc2, 0xc6, 0xcc, 0xd8, 0x30, 0x60, 0xdc, 0x86, 0x0c, 0x18, 0x3e, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0xc2, 0xc6, 0xcc, 0xd8, 0x30, 0x66, 0xce, 0x9e, 0x3e, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30,
        0x00, 0x30, 0x30, 0x30, 0x78, 0x78, 0x78, 0x78, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36,
        0x6c, 0xd8, 0x6c, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd8, 0x6c, 0x36,
        0x6c, 0xd8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x88, 0x22, 0x88, 0x22, 0x88, 0x22, 0x88, 0x22, 0x88,
        0x22, 0x88, 0x22, 0x88, 0x22, 0x88, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa,
        0x55, 0xaa, 0x55, 0xaa, 0xdd, 0x77, 0xdd, 0x77, 0xdd, 0x77, 0xdd, 0x77, 0xdd, 0x77, 0xdd, 0x77, 0xdd, 0x77,
        0xdd, 0x77, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
        0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0xf8, 0xf8, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
        0x18, 0x18, 0x18, 0xf8, 0xf8, 0x18, 0x18, 0xf8, 0xf8, 0x18, 0x18, 0x18, 0x18, 0x18, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0xf6, 0xf6, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xfe, 0xfe, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xf8, 0x18,
        0x18, 0xf8, 0xf8, 0x18, 0x18, 0x18, 0x18, 0x18, 0x36, 0x36, 0x36, 0x36, 0x36, 0xf6, 0xf6, 0x06, 0x06, 0xf6,
        0xf6, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xfe, 0x06, 0x06, 0xf6, 0xf6, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0xf6, 0xf6, 0x06, 0x06, 0xfe, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0xfe, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18,
        0x18, 0x18, 0x18, 0xf8, 0xf8, 0x18, 0x18, 0xf8, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xf8, 0xf8, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
        0x18, 0x1f, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0xff,
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x18,
        0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x1f, 0x1f, 0x18, 0x18, 0x18,
        0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0xff, 0xff, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
        0x18, 0x18, 0x18, 0x18, 0x18, 0x1f, 0x1f, 0x18, 0x18, 0x1f, 0x1f, 0x18, 0x18, 0x18, 0x18, 0x18, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x37, 0x37, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x37, 0x37, 0x30, 0x30, 0x3f, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f,
        0x3f, 0x30, 0x30, 0x37, 0x37, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0xf7, 0xf7, 0x00,
        0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xf7,
        0xf7, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x37, 0x37, 0x30, 0x30, 0x37, 0x37, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x36, 0x36, 0x36, 0x36, 0x36, 0xf7, 0xf7, 0x00, 0x00, 0xf7, 0xf7, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x18, 0x18, 0x18, 0x18, 0x18, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff, 0xff, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x3f,
        0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x1f, 0x1f, 0x18, 0x18, 0x1f,
        0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x1f, 0x18, 0x18, 0x1f, 0x1f, 0x18,
        0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x3f, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0xff, 0xff, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x18, 0x18, 0x18, 0x18, 0x18, 0xff, 0xff, 0x18, 0x18, 0xff, 0xff, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
        0x18, 0x18, 0x18, 0x18, 0x18, 0xf8, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x1f, 0x1f, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
        0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
        0x0f, 0x0f, 0x0f, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xd6, 0xdc, 0xc8, 0xc8, 0xdc, 0xd6, 0x76, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x78, 0xcc, 0xcc, 0xcc, 0xd8, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xd8, 0xc0, 0xc0, 0x00, 0x00, 0x00,
        0xfe, 0xc6, 0xc6, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x7e, 0xfe, 0x24, 0x24, 0x24, 0x24, 0x66, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xfe, 0xc2, 0x60,
        0x30, 0x18, 0x30, 0x60, 0xc2, 0xfe, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0xc8, 0xcc,
        0xcc, 0xcc, 0xcc, 0xcc, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x76, 0x6c, 0x60, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0xfc, 0x98, 0x18, 0x18, 0x18, 0x18,
        0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x30, 0x30, 0x78, 0xcc, 0xcc, 0xcc, 0x78, 0x30, 0x30, 0xfc, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x38, 0x6c, 0xc6, 0xc6, 0xc6, 0xfe, 0xc6, 0xc6, 0xc6, 0x6c, 0x38, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x38, 0x6c, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0x6c, 0x6c, 0x6c, 0xee, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x78, 0xcc, 0x60, 0x30, 0x78, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x76, 0xbb, 0x99, 0x99, 0xdd, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x06, 0x3c, 0x6c,
        0xce, 0xd6, 0xd6, 0xe6, 0x6c, 0x78, 0xc0, 0x80, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x30, 0x60, 0xc0, 0xc0, 0xfe,
        0xc0, 0xc0, 0x60, 0x30, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x6c, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6, 0xc6,
        0xc6, 0xc6, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x00, 0xfe, 0x00, 0x00, 0xfe, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0xfc, 0x30, 0x30, 0x00, 0x00, 0xfc, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x30, 0x18, 0x0c, 0x18, 0x30, 0x60, 0x00, 0xfc, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x18, 0x30, 0x60, 0xc0, 0x60, 0x30, 0x18, 0x00, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1c, 0x36, 0x36, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x18, 0x18, 0x18, 0x18,
        0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0xd8, 0xd8, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30,
        0x00, 0xfc, 0x00, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0xdc, 0x00,
        0x76, 0xdc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0xcc, 0xcc, 0xcc, 0x78, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0f, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0xcc, 0x6c, 0x3c, 0x1c, 0x0c, 0x00, 0x00,
        0x00, 0xd8, 0xec, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38,
        0x6c, 0x0c, 0x18, 0x30, 0x60, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};