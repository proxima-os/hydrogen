#include "arch/stack.h"
#include "init/cmdline.h"
#include "kernel/compiler.h"
#include "limine.h"
#include "mem/memmap.h"
#include "proc/rcu.h"
#include "proc/sched.h"
#include "sections.h"
#include "util/panic.h"
#include <stddef.h>

__attribute__((used, section(".requests0"))) static LIMINE_REQUESTS_START_MARKER;
__attribute__((used, section(".requests2"))) static LIMINE_REQUESTS_END_MARKER;

LIMINE_REQ LIMINE_BASE_REVISION(3);

_Alignas(KERNEL_STACK_ALIGN) static unsigned char init_stack[KERNEL_STACK_SIZE];

static void kernel_init(void *ctx) {
}

USED _Noreturn void kernel_main(void) {
    parse_command_line();
    sched_init();
    rcu_init();
    memmap_init();

    thread_t init_thread;
    int error = sched_create_thread(&init_thread, kernel_init, NULL, init_stack, sizeof(init_stack));
    if (unlikely(error)) panic("failed to create init thread (%d)", error);
    sched_wake(&init_thread);
    thread_deref(&init_thread);

    sched_idle();
}
