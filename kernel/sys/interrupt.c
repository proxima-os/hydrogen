#include "drv/interrupt.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "util/handle.h"
#include "util/object.h"
#include <hydrogen/interrupt.h>
#include <hydrogen/types.h>

hydrogen_ret_t hydrogen_interrupt_wait(int irq, uint64_t deadline, unsigned flags) {
    object_rights_t rights = HYDROGEN_INTERRUPT_WAIT;

    if (flags & HYDROGEN_IRQ_WAIT_CLAIM) rights |= HYDROGEN_INTERRUPT_CLAIM;

    handle_data_t data;
    int error = hnd_resolve(&data, irq, OBJECT_INTERRUPT, rights);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = interrupt_wait((interrupt_t *)data.object, deadline, flags);
    obj_deref(data.object);
    return ret;
}

int hydrogen_interrupt_claim(int irq, size_t id) {
    handle_data_t data;
    int error = hnd_resolve(&data, irq, OBJECT_INTERRUPT, HYDROGEN_INTERRUPT_CLAIM);
    if (unlikely(error)) return error;

    error = interrupt_claim((interrupt_t *)data.object, id);
    obj_deref(data.object);
    return error;
}
