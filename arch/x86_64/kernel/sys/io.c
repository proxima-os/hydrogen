#include "cpu/cpudata.h"
#include "errno.h"
#include "proc/process.h"
#include <hydrogen/x86_64/io.h>

int hydrogen_x86_64_enable_io_access(void) {
    if (geteuid(current_thread->process) != 0) return EPERM;
    current_thread->user_ctx->rflags |= 3ul << 12;
    current_thread->arch.io_access = true;
    return 0;
}

void hydrogen_x86_64_disable_io_access(void) {
    current_thread->user_ctx->rflags &= ~(3ul << 12);
    current_thread->arch.io_access = false;
}
