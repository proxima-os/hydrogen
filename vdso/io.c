#include "hydrogen/io.h"
#include "hydrogen/error.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "syscall.h"

hydrogen_error_t hydrogen_io_enable(hydrogen_handle_t io) {
    UNUSED int ret;
    hydrogen_error_t error;
    SYSCALL1(SYSCALL_IO_ENABLE, io);
    return error;
}

void hydrogen_io_disable(void) {
    UNUSED int ret, error;
    SYSCALL0(SYSCALL_IO_DISABLE);
}
