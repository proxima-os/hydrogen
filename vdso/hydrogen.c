#include "arch/syscall.h"
#include "kernel/syscall.h"
#include "string.h"
#include "vdso-config.h"
#include "vdso.h"
#include <hydrogen/hydrogen.h>
#include <hydrogen/types.h>

EXPORT size_t hydrogen_get_kernel_name(void *buffer, size_t size) {
    static const char name[] = "Hydrogen";
    size_t len = sizeof(name) - 1;

    memcpy(buffer, name, len < size ? len : size);
    return len;
}

EXPORT size_t hydrogen_get_kernel_release(void *buffer, size_t size) {
    static const char release[] = HYDROGEN_RELEASE;
    size_t len = sizeof(release) - 1;

    memcpy(buffer, release, len < size ? len : size);
    return len;
}

EXPORT size_t hydrogen_get_kernel_version(void *buffer, size_t size) {
    static const char version[] = HYDROGEN_VERSION;
    size_t len = sizeof(version) - 1;

    memcpy(buffer, version, len < size ? len : size);
    return len;
}

EXPORT hydrogen_ret_t hydrogen_get_host_name(void *buffer, size_t size) {
    return SYSCALL2(SYSCALL_GET_HOST_NAME, buffer, size);
}

EXPORT int hydrogen_set_host_name(const void *name, size_t size) {
    return SYSCALL2(SYSCALL_SET_HOST_NAME, name, size).error;
}
