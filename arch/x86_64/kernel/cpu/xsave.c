#include "x86_64/xsave.h"
#include "kernel/compiler.h"
#include "mem/vmalloc.h"
#include "sections.h"
#include "string.h"
#include "util/printk.h"
#include "x86_64/cpu.h"
#include "x86_64/cpuid.h"
#include "x86_64/xcr.h"
#include <stdint.h>

#define XCR0_X87 (1ul << 0)
#define XCR0_SSE (1ul << 1)
#define XCR0_AVX (1ul << 2)
#define XCR0_AVX512 (7ul << 5)

#define XCR0_MASK (XCR0_AVX512 | XCR0_AVX | XCR0_SSE | XCR0_X87)

typedef enum {
    CTX_FXSAVE,
    CTX_XSAVE,
    CTX_XSAVEOPT,
} ctx_style_t;

static ctx_style_t ctx_style;
static size_t ctx_size;
INIT_DATA static uint64_t xcr0_value;

INIT_TEXT static void determine_mode(void) {
    if (!x86_64_cpu_features.xsave) {
        ctx_style = CTX_FXSAVE;
        ctx_size = 512;
        return;
    }

    // Enable all the features we support
    unsigned eax, ebx, ecx, edx;
    cpuid2(0x0d, 0, &eax, &ebx, &ecx, &edx);
    xcr0_value = ((uint64_t)edx << 32) | eax;
    xcr0_value &= XCR0_MASK;
    x86_64_write_xcr(0, xcr0_value);

    // Figure out how big the context is
    cpuid2(0x0d, 0, &eax, &ebx, &ecx, &edx);
    ctx_size = ebx;

    // Determine what style to use
    cpuid2(0x0d, 1, &eax, &ebx, &ecx, &edx);

    if ((eax & 1) != 0) {
        ctx_style = CTX_XSAVEOPT;
    } else {
        ctx_style = CTX_XSAVE;
    }
}

INIT_TEXT void x86_64_xsave_init(void) {
    determine_mode();
    printk("xsave: context is %z bytes (style %d)\n", ctx_size, ctx_style);
}

INIT_TEXT void x86_64_xsave_init_local(void) {
    if (ctx_style == CTX_FXSAVE) return;
    x86_64_write_xcr(0, xcr0_value);
}

void *x86_64_xsave_alloc(void) {
    void *ptr = vmalloc_aligned(ctx_size);
    if (unlikely(!ptr)) return NULL;

    if (ctx_style != CTX_FXSAVE) {
        // clear header so xsave doesn't get confused
        ASSERT(ctx_size >= 576);
        memset(ptr + 512, 0, 64);
    }

    x86_64_xsave_save(ptr);
    return ptr;
}

void x86_64_xsave_free(void *area) {
    vfree(area, ctx_size);
}

void x86_64_xsave_save(void *area) {
    switch (ctx_style) {
    case CTX_FXSAVE: asm("fxsaveq %0" ::"m"(*(char(*)[ctx_size])area) : "memory"); break;
    case CTX_XSAVE: asm("xsaveq %0" ::"m"(*(char(*)[ctx_size])area), "d"(-1), "a"(-1) : "memory"); break;
    case CTX_XSAVEOPT: asm("xsaveoptq %0" ::"m"(*(char(*)[ctx_size])area), "d"(-1), "a"(-1) : "memory"); break;
    }
}

void x86_64_xsave_restore(void *area) {
    switch (ctx_style) {
    case CTX_FXSAVE: asm("fxrstorq %0" ::"m"(*(char(*)[ctx_size])area) : "memory"); break;
    case CTX_XSAVE:
    case CTX_XSAVEOPT: asm("xrstorq %0" ::"m"(*(char(*)[ctx_size])area), "d"(-1), "a"(-1) : "memory"); break;
    }
}

void x86_64_xsave_reset(void *area) {
    memset(area, 0, ctx_size);
    x86_64_xsave_restore(area);
    uint32_t mxcsr = 0x1f80;
    asm("ldmxcsr %0" ::"m"(mxcsr));
}
