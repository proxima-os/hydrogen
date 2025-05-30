#include "arch/syscall.h"
#include "kernel/syscall.h"
#include "vdso.h"
#include <hydrogen/interrupt.h>
#include <hydrogen/types.h>

EXPORT int hydrogen_interrupt_wait(int irq, uint64_t deadline, unsigned int flags) {
    return SYSCALL3(SYSCALL_INTERRUPT_WAIT, irq, deadline, flags).error;
}

EXPORT int hydrogen_interrupt_complete(int irq) {
    return SYSCALL1(SYSCALL_INTERRUPT_COMPLETE, irq).error;
}
