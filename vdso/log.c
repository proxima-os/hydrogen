#include "hydrogen/log.h"
#include "hydrogen/error.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "syscall.h"

hydrogen_error_t hydrogen_log_write(hydrogen_handle_t log, const void *data, size_t size) {
    UNUSED int ret;
    hydrogen_error_t error;
    SYSCALL3(SYSCALL_LOG_WRITE, log, data, size);
    return error;
}
