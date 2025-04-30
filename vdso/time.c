#include "kernel/time.h"
#include "hydrogen/time.h"
#include "kernel/kvmclock.h"
#include "kernel/syscall.h"
#include "kernel/vdso.h"
#include "syscall.h"
#include "vdso.h"
#include <stdint.h>

static uint64_t get_time_syscall(void) {
    return ASSERT_OK(SYSCALL0(SYSCALL_GET_TIME)).integer;
}

static uint64_t get_time_kvmclock(void) {
    return kvmclock_read(&vdso_info.time.kvmclock);
}

static uint64_t get_time_tsc(void) {
    return timeconv_apply(vdso_info.time.tsc, read_tsc_value());
}

static uint64_t (*resolve_get_time(void))(void) {
    switch (vdso_info.time.style) {
    case VDSO_TIME_SYSCALL: return get_time_syscall;
    case VDSO_TIME_KVMCLOCK: return get_time_kvmclock;
    case VDSO_TIME_TSC: return get_time_tsc;
    default: __builtin_unreachable();
    }
}

__attribute__((ifunc("resolve_get_time"))) EXPORT uint64_t hydrogen_get_time(void);

EXPORT int hydrogen_sleep(uint64_t deadline) {
    return SYSCALL1(SYSCALL_SLEEP, deadline).error;
}
