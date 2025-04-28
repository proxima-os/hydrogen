#include "hydrogen/io.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "syscall.h"
#include "vdso.h"

EXPORT int hydrogen_io_enable(hydrogen_handle_t io) {
    UNUSED int ret;
    int error;
    SYSCALL1(SYSCALL_IO_ENABLE, io);
    return error;
}

EXPORT void hydrogen_io_disable(void) {
    UNUSED int ret, error;
    SYSCALL0(SYSCALL_IO_DISABLE);
}
