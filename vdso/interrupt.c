#include "arch/syscall.h"
#include "kernel/syscall.h"
#include "vdso.h"
#include <hydrogen/interrupt.h>
#include <hydrogen/types.h>

EXPORT hydrogen_ret_t hydrogen_interrupt_wait(int irq, uint64_t deadline, unsigned int flags) {
    return SYSCALL3(SYSCALL_INTERRUPT_WAIT, irq, deadline, flags);
}

EXPORT int hydrogen_interrupt_claim(int irq, size_t id) {
    return SYSCALL2(SYSCALL_INTERRUPT_CLAIM, irq, id).error;
}
