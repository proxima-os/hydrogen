#include "hydrogen/io.h"
#include "kernel/syscall.h"
#include "syscall.h"
#include "vdso.h"

EXPORT int hydrogen_io_enable(hydrogen_handle_t io) {
    return SYSCALL1(SYSCALL_IO_ENABLE, io).error;
}

EXPORT void hydrogen_io_disable(void) {
    ASSERT_OK(SYSCALL0(SYSCALL_IO_DISABLE));
}
