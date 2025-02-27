#include "cpu/idt.h"
#include "asm/msr.h"
#include "asm/tables.h"
#include "cpu/cpu.h"
#include "cpu/gdt.h"
#include "cpu/irqvecs.h"
#include "kernel/compiler.h"
#include "util/panic.h"
#include <stdint.h>

typedef struct {
    uint16_t offset0;
    uint16_t selector;
    uint8_t ist;
    uint8_t flags;
    uint16_t offset1;
    uint32_t offset2;
} __attribute__((aligned(8), packed)) idt_entry_t;

static idt_entry_t idt[256];
static struct {
    idt_handler_t handler;
    void *ctx;
} handlers[256];

extern const uintptr_t idt_stubs[256];

void init_idt(void) {
    for (int i = 0; i < 256; i++) {
        uintptr_t stub = idt_stubs[i];
        if (!stub) continue;

        idt[i].offset0 = stub;
        idt[i].offset1 = stub >> 16;
        idt[i].offset2 = stub >> 32;
        idt[i].selector = SEL_KCODE;
        idt[i].flags = 0x8e;
    }

    // These are allowed to be called by userspace.
    idt[VEC_DEBUG].flags |= 1 << 5;
    idt[VEC_BREAKPOINT].flags |= 3 << 5;

    // These can share a stack because all of them are fatal. If they're nested, the previous one's stack will get
    // overwritten, but that's fine because it won't be returned to anyway.
    idt[VEC_DEBUG].ist = 1;
    idt[VEC_NMI].ist = 1;
    idt[VEC_DOUBLE_FAULT].ist = 1;
    idt[VEC_MACHINE_CHECK].ist = 1;
}

void setup_idt(void) {
    load_idt(idt, sizeof(idt));
}

USED void idt_dispatch(idt_frame_t *frame) {
    if (cpu_features.smap) asm("clac");

    idt_handler_t handler = handlers[frame->vector].handler;
    ASSERT(handler != NULL);
    handler(frame, handlers[frame->vector].ctx);
}

void idt_install(int vector, idt_handler_t handler, void *ctx) {
    // don't need to use atomics here because the interrupt must not be enabled until after the function returns
    ASSERT(handlers[vector].handler == NULL);
    handlers[vector].ctx = ctx;
    handlers[vector].handler = handler;
}

void idt_uninstall(UNUSED int vector, UNUSED idt_handler_t handler) {
    // guarded by NDEBUG because it's only useful for detecting bugs; the interrupt must be disabled before
    // it is allowed to be uninstalled, so if there are no bugs the handler won't get called again anyway.
    // the only reason this is done at all is because it turns a spurious handler call into a (much more noticeable)
    // null pointer dereference
#ifndef NDEBUG
    ASSERT(handlers[vector].handler == handler);
    handlers[vector].handler = NULL;
#endif
}

bool idt_paranoid_entry(idt_frame_t *frame) {
    ASSERT(idt[frame->vector].ist != 0);

    uintptr_t cur_gsbase = rdmsr(MSR_GS_BASE);
    uintptr_t wanted_gsbase = *(uintptr_t *)(frame + 1);

    if (cur_gsbase != wanted_gsbase) {
        asm("swapgs" ::: "memory");
        ASSERT(rdmsr(MSR_GS_BASE) == wanted_gsbase);
        return true;
    } else {
        return false;
    }
}

void idt_paranoid_exit(bool ret) {
    if (ret) {
        asm("swapgs" ::: "memory");
    }
}
