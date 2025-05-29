#include "arch/syscall.h"
#include "kernel/x86_64/syscall.h"
#include "vdso.h"
#include <hydrogen/x86_64/io.h>

EXPORT int hydrogen_x86_64_enable_io_access(void) {
    return SYSCALL0(X86_64_SYSCALL_ENABLE_IO_ACCESS).error;
}

EXPORT void hydrogen_x86_64_disable_io_access(void) {
    SYSCALL0(X86_64_SYSCALL_DISABLE_IO_ACCESS);
}
