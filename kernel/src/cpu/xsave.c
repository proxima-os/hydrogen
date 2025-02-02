#include "cpu/xsave.h"
#include "asm/cpuid.h"
#include "asm/cr.h"
#include "asm/xcr.h"
#include "cpu/cpu.h"
#include "kernel/compiler.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "util/logging.h"
#include "util/panic.h"
#include <stdbool.h>

#define XCR0_X87 (1ul << 0)
#define XCR0_SSE (1ul << 1)
#define XCR0_AVX (1ul << 2)
#define XCR0_AVX512 (7ul << 5)

#define XCR0_MASK (XCR0_AVX512 | XCR0_AVX | XCR0_SSE | XCR0_X87)

typedef enum {
    CTX_FXSAVE,
    CTX_XSAVE,
    CTX_XSAVEOPT,
} xsave_style_t;

static xsave_style_t ctx_style;
static size_t context_size;
static uint64_t xcr0_value;
static bool global_init_done;

static void do_global_init(void) {
    if (!cpu_features.xsave) {
        ctx_style = CTX_FXSAVE;
        context_size = 512;
        return;
    }

    write_cr4(read_cr4() | CR4_OSXSAVE);
    ctx_style = CTX_XSAVE;

    // Enable features
    unsigned eax, ebx, ecx, edx;
    cpuid2(0x0d, 0, &eax, &ebx, &ecx, &edx);
    xcr0_value = ((uint64_t)edx << 32) | eax;
    xcr0_value &= XCR0_MASK;
    write_xcr(0, xcr0_value);

    // Get the size of the context for the features we selected
    cpuid2(0x0d, 0, &eax, &ebx, &ecx, &edx);
    context_size = ebx;

    // Detect features for xsave itself
    cpuid2(0x0d, 1, &eax, &ebx, &ecx, &edx);
    if (eax & 1) ctx_style = CTX_XSAVEOPT;
}

void init_xsave(void) {
    if (!global_init_done) {
        do_global_init();
        printk("xsave: context is %U bytes (style %d)\n", context_size, ctx_style);
        global_init_done = true;

        current_thread->xsave = vmalloc(context_size);
        if (unlikely(!current_thread->xsave)) panic("failed to allocate xsave area for idle thread");
        memset(current_thread->xsave, 0, context_size);
        xreset();
    } else if (ctx_style != CTX_FXSAVE) {
        write_cr4(read_cr4() | CR4_OSXSAVE);
        write_xcr(0, xcr0_value);
        xreset();
    }
}

static void do_xsave(void *ptr) {
    switch (ctx_style) {
    case CTX_FXSAVE: asm("fxsaveq (%0)" ::"r"(ptr)); break;
    case CTX_XSAVE: asm("xsaveq (%0)" ::"r"(ptr), "d"(-1), "a"(-1)); break;
    case CTX_XSAVEOPT: asm("xsaveoptq (%0)" ::"r"(ptr), "d"(-1), "a"(-1)); break;
    }
}

void *xsave_alloc(void) {
    void *ptr = vmalloc(context_size);
    if (unlikely(!ptr)) return NULL;

    // clear header, otherwise xsave gets confused
    if (ctx_style != CTX_FXSAVE) {
        ASSERT(context_size >= 576);
        memset(ptr + 512, 0, 64);
    }

    do_xsave(ptr);
    return ptr;
}

void xsave_free(void *ptr) {
    vmfree(ptr, context_size);
}

void xsave(void) {
    do_xsave(current_thread->xsave);
}

void xrestore(void) {
    switch (ctx_style) {
    case CTX_FXSAVE: asm("fxrstorq (%0)" ::"r"(current_thread->xsave)); break;
    case CTX_XSAVE:
    case CTX_XSAVEOPT: asm("xrstorq (%0)" ::"r"(current_thread->xsave), "d"(-1), "a"(-1)); break;
    }
}

void xreset(void) {
    memset(current_thread->xsave, 0, context_size);
    xrestore();
    uint32_t mxcsr = 0x1f80;
    asm("ldmxcsr %0" ::"m"(mxcsr));
}
