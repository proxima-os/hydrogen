#include "hydrogen/io.h"
#include "cpu/cpu.h"
#include "kernel/compiler.h"
#include "util/handle.h"
#include "util/io.h"
#include "util/object.h"

// No ops necessary, never freed
object_t io_object = {.references = 1};

bool is_io_object(object_t *obj) {
    return obj == &io_object;
}

int hydrogen_io_enable(hydrogen_handle_t io) {
    int error = resolve(io, NULL, is_io_object, 0);
    if (unlikely(error)) return error;

    // Set IOPL to 3
    current_thread->user_regs->rflags |= 3ul << 12;
    return 0;
}

void hydrogen_io_disable(void) {
    // Clear IOPL
    current_thread->user_regs->rflags &= ~(3ul << 12);
}
