#include "drv/interrupt.h"
#include "kernel/compiler.h"
#include "util/handle.h"
#include "util/object.h"
#include <hydrogen/interrupt.h>
#include <hydrogen/types.h>

int hydrogen_interrupt_wait(int irq, uint64_t deadline, unsigned flags) {
    object_rights_t rights = HYDROGEN_INTERRUPT_WAIT;

    if (flags & HYDROGEN_IRQ_WAIT_COMPLETE) rights |= HYDROGEN_INTERRUPT_COMPLETE;

    handle_data_t data;
    int error = hnd_resolve(&data, irq, OBJECT_INTERRUPT, rights);
    if (unlikely(error)) return error;

    error = interrupt_wait((interrupt_t *)data.object, deadline, flags);
    obj_deref(data.object);
    return error;
}

int hydrogen_interrupt_complete(int irq) {
    handle_data_t data;
    int error = hnd_resolve(&data, irq, OBJECT_INTERRUPT, HYDROGEN_INTERRUPT_COMPLETE);
    if (unlikely(error)) return error;

    error = interrupt_complete((interrupt_t *)data.object);
    obj_deref(data.object);
    return error;
}
