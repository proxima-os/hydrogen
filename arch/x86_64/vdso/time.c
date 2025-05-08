#include "hydrogen/time.h"
#include "arch/syscall.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "kernel/time.h"
#include "kernel/vdso.h"
#include "kernel/x86_64/kvmclock.h"
#include "kernel/x86_64/tsc.h"
#include "vdso.h"

static uint64_t get_ns_since_boot_syscall(void) {
    return SYSCALL0(SYSCALL_GET_NANOSECONDS_SINCE_BOOT).integer;
}

static uint64_t get_ns_since_boot_kvmclock(void) {
    return x86_64_read_kvmclock(&vdso_info.arch.kvmclock);
}

static uint64_t get_ns_since_boot_tsc(void) {
    return timeconv_apply(vdso_info.arch.tsc2ns_conv, x86_64_read_tsc());
}

static uint64_t (*resolve_ns_since_boot(void))(void) {
    switch (vdso_info.arch.time_source) {
    case X86_64_TIME_SYSCALL: return get_ns_since_boot_syscall;
    case X86_64_TIME_KVMCLOCK: return get_ns_since_boot_kvmclock;
    case X86_64_TIME_TSC: return get_ns_since_boot_tsc;
    default: UNREACHABLE();
    }
}

__attribute__((ifunc("resolve_ns_since_boot"))) EXPORT uint64_t hydrogen_get_nanoseconds_since_boot(void);
