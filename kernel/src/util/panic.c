#include "util/panic.h"
#include "asm/idle.h"
#include "asm/irq.h"
#include "util/logging.h"
#include <stdbool.h>

static bool panicking;

_Noreturn void panic(const char *format, ...) {
    disable_irq();

    if (!__atomic_exchange_n(&panicking, true, __ATOMIC_RELAXED)) {
        va_list args;
        va_start(args, format);
        printk("panic: ");
        vprintk(format, args);
        printk("\n");
        va_end(args);
    }

    for (;;) cpu_idle();
}
