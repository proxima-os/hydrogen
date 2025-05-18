#include "x86_64/xsave.h"
#include "init/task.h"
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
size_t x86_64_xsave_size;
static uint64_t xcr0_value;

INIT_TEXT static void determine_mode(void) {
    if (!x86_64_cpu_features.xsave) {
        ctx_style = CTX_FXSAVE;
        x86_64_xsave_size = 512;
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
    x86_64_xsave_size = ebx;

    // Determine what style to use
    cpuid2(0x0d, 1, &eax, &ebx, &ecx, &edx);

    if ((eax & 1) != 0) {
        ctx_style = CTX_XSAVEOPT;
    } else {
        ctx_style = CTX_XSAVE;
    }
}

INIT_TEXT static void xsave_init(void) {
    determine_mode();
    printk("xsave: context is %z bytes (style %d)\n", x86_64_xsave_size, ctx_style);
}

INIT_DEFINE_EARLY(x86_64_xsave, xsave_init);

INIT_TEXT static void xsave_init_local(void) {
    if (ctx_style == CTX_FXSAVE) return;
    x86_64_write_xcr(0, xcr0_value);
}

INIT_DEFINE_EARLY_AP(x86_64_xsave_ap, xsave_init_local);

void *x86_64_xsave_alloc(void) {
    void *ptr = vmalloc_aligned(x86_64_xsave_size);
    if (unlikely(!ptr)) return NULL;

    x86_64_xsave_reinit(ptr);
    return ptr;
}

void x86_64_xsave_free(void *area) {
    vfree(area, x86_64_xsave_size);
}

typedef struct {
    uint16_t fcw;
    uint16_t fsw;
    uint8_t ftw;
    uint8_t reserved1;
    uint16_t fop;
    uint64_t fip;
    uint64_t fdp;
    uint32_t mxcsr;
    uint32_t mxcsr_mask;
    struct {
        uint64_t data[2];
    } mm[8];
    struct {
        uint64_t data[2];
    } xmm[16];
    uint64_t reserved2[6];
    uint64_t unused[6];
} fxsave_area_t;

typedef struct {
    fxsave_area_t legacy;
    uint64_t xstate_bv;
    uint64_t xcomp_bv;
    uint64_t reserved[6];
    unsigned char ext[];
} xsave_area_t;

void x86_64_xsave_reinit(void *area) {
    if (ctx_style != CTX_FXSAVE) {
        // clear header so xsave doesn't get confused
        xsave_area_t *ctx = area;
        ctx->xstate_bv = 0;
        ctx->xcomp_bv = 0;
        memset(ctx->reserved, 0, sizeof(ctx->reserved));
    }

    x86_64_xsave_save(area);
}

void x86_64_xsave_sanitize(void *area) {
    // We need to protect against the following scenarios:
    // - (CTX_XSAVE*) Bit 63 of XCOMP_BV is 1
    // - (CTX_XSAVE*) A bit is set in XSTATE_BV but not in xcr0
    // - (CTX_XSAVE*) Bytes 8:23 of the XSAVE header are not zero
    // - MXCSR value has reserved bits set

    fxsave_area_t *ctx = area;
    ctx->mxcsr &= 0xffff;

    if (ctx_style == CTX_FXSAVE) return;

    xsave_area_t *xctx = area;
    xctx->xstate_bv &= xcr0_value;
    xctx->xcomp_bv = 0;
    memset(xctx->reserved, 0, sizeof(xctx->reserved));
}

void x86_64_xsave_save(void *area) {
    switch (ctx_style) {
    case CTX_FXSAVE: asm("fxsaveq %0" ::"m"(*(char(*)[x86_64_xsave_size])area) : "memory"); break;
    case CTX_XSAVE: asm("xsaveq %0" ::"m"(*(char(*)[x86_64_xsave_size])area), "d"(-1), "a"(-1) : "memory"); break;
    case CTX_XSAVEOPT: asm("xsaveoptq %0" ::"m"(*(char(*)[x86_64_xsave_size])area), "d"(-1), "a"(-1) : "memory"); break;
    }
}

void x86_64_xsave_restore(void *area) {
    switch (ctx_style) {
    case CTX_FXSAVE: asm("fxrstorq %0" ::"m"(*(char(*)[x86_64_xsave_size])area) : "memory"); break;
    case CTX_XSAVE:
    case CTX_XSAVEOPT: asm("xrstorq %0" ::"m"(*(char(*)[x86_64_xsave_size])area), "d"(-1), "a"(-1) : "memory"); break;
    }
}

void x86_64_xsave_reset(void *area) {
    memset(area, 0, x86_64_xsave_size);
    fxsave_area_t *ctx = area;
    ctx->mxcsr = 0x1f80;

    x86_64_xsave_restore(area);
}
