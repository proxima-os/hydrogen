#include "util/panic.h"
#include "arch/idle.h"
#include "arch/irq.h"
#include "cpu/cpudata.h"
#include "cpu/smp.h"
#include "kernel/compiler.h"
#include "util/printk.h"
#include <stdbool.h>

static _Noreturn void do_halt(void *ctx) {
    for (;;) {
        cpu_idle();
    }
}

_Noreturn void panic(const char *format, ...) {
    static bool panicking;

    disable_irq();

    if (!__atomic_exchange_n(&panicking, true, __ATOMIC_RELAXED)) {
        printk_lock(); // never unlock it after this
        smp_call_remote(NULL, SMP_REMOTE_HALT);

        va_list args;
        va_start(args, format);
        printk_raw_format("kernel panic on cpu %U: ", this_cpu_read(id));
        printk_raw_formatv(format, args);
        printk_raw_format("\n");
        printk_raw_flush();
        va_end(args);
    }

    do_halt(NULL);
}

_Noreturn void hydrogen_assert_fail(const char *expr, const char *func, const char *file, int line) {
    panic("assertion `%s` failed in %s at %s:%d", expr, func, file, line);
}
