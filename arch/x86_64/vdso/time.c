#include "kernel/time.h"
#include "arch/syscall.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "kernel/vdso.h"
#include "kernel/x86_64/kvmclock.h"
#include "kernel/x86_64/tsc.h"
#include "vdso.h"
#include <hydrogen/time.h>
#include <stdint.h>

static uint64_t boot_time_syscall(void) {
    return SYSCALL0(SYSCALL_GET_NANOSECONDS_SINCE_BOOT).integer;
}

static __int128_t real_time_syscall(void) {
    return real_time_from_boot_time(boot_time_syscall());
}

static uint64_t boot_time_kvmclock(void) {
    return x86_64_read_kvmclock(&vdso_info.arch.kvmclock) - vdso_info.arch.time_offset;
}

static __int128_t real_time_kvmclock(void) {
    return real_time_from_boot_time(boot_time_kvmclock());
}

static uint64_t boot_time_tsc(void) {
    return timeconv_apply(vdso_info.arch.tsc2ns_conv, x86_64_read_tsc()) - vdso_info.arch.time_offset;
}

static __int128_t real_time_tsc(void) {
    return real_time_from_boot_time(boot_time_tsc());
}

static uint64_t (*resolve_boot_time(void))(void) {
    switch (vdso_info.arch.time_source) {
    case X86_64_TIME_SYSCALL: return boot_time_syscall;
    case X86_64_TIME_KVMCLOCK: return boot_time_kvmclock;
    case X86_64_TIME_TSC: return boot_time_tsc;
    default: UNREACHABLE();
    }
}

__attribute__((ifunc("resolve_boot_time"))) EXPORT uint64_t hydrogen_boot_time(void);

static __int128_t (*resolve_real_time(void))(void) {
    switch (vdso_info.arch.time_source) {
    case X86_64_TIME_SYSCALL: return real_time_syscall;
    case X86_64_TIME_KVMCLOCK: return real_time_kvmclock;
    case X86_64_TIME_TSC: return real_time_tsc;
    default: UNREACHABLE();
    }
}

__attribute__((ifunc("resolve_real_time"))) EXPORT __int128_t hydrogen_get_real_time(void);
