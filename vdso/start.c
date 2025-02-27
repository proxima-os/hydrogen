#include "hydrogen/init.h"
#include "hydrogen/log.h"
#include "hydrogen/thread.h"
#include <stdint.h>

__attribute__((used)) _Noreturn void vdso_start(hydrogen_init_info_t *info) {
    hydrogen_log_write(info->log_handle, "Hello from userspace!\n", 22);
    hydrogen_thread_exit();
}
