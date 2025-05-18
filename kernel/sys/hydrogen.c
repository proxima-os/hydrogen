#include "hydrogen/hydrogen.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "hydrogen/types.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "proc/mutex.h"
#include "proc/process.h"
#include "sections.h"
#include "string.h"
#include "sys/syscall.h"
#include "util/panic.h"
#include <stdint.h>

static void *host_name;
static size_t host_name_size;
static mutex_t host_name_lock;

INIT_TEXT static void host_name_init(void) {
    static const char default_hostname[] = "hydrogen";
    host_name_size = sizeof(default_hostname) - 1;
    host_name = vmalloc(host_name_size);
    if (unlikely(!host_name)) panic("failed to allocate host name buffer");
    memcpy(host_name, default_hostname, host_name_size);
}

INIT_DEFINE(hostname, host_name_init);

hydrogen_ret_t hydrogen_get_host_name(void *buffer, size_t size) {
    int error = verify_user_buffer((uintptr_t)buffer, size);
    if (unlikely(error)) return ret_error(error);

    mutex_acq(&host_name_lock, 0, false);

    size_t full_size = host_name_size;
    error = user_memcpy(buffer, host_name, full_size < size ? full_size : size);

    mutex_rel(&host_name_lock);
    return RET_MAYBE(integer, error, full_size);
}

int hydrogen_set_host_name(const void *name, size_t size) {
    int error = verify_user_buffer((uintptr_t)name, size);
    if (unlikely(error)) return error;

    if (unlikely(getuid(current_thread->process) != 0)) return EPERM;

    void *buffer = vmalloc(size);
    if (unlikely(!buffer)) return ENOMEM;

    error = user_memcpy(buffer, name, size);
    if (unlikely(error)) {
        vfree(buffer, size);
        return error;
    }

    mutex_acq(&host_name_lock, 0, false);

    vfree(host_name, host_name_size);
    host_name = buffer;
    host_name_size = size;

    mutex_rel(&host_name_lock);
    return 0;
}
