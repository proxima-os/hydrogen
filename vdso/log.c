#include "hydrogen/log.h"
#include "kernel/syscall.h"
#include "syscall.h"
#include "vdso.h"

EXPORT int hydrogen_log_write(hydrogen_handle_t log, const void *data, size_t size) {
    return SYSCALL3(SYSCALL_LOG_WRITE, log, data, size).error;
}
