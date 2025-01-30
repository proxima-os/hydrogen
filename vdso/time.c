#include "hydrogen/time.h"
#include "kernel/time.h"
#include "kernel/vdso.h"

static uint64_t ns_since_boot(void) {
    return timeconv_apply(tsc2ns_conv, __builtin_ia32_rdtsc() - __atomic_load_n(&boot_tsc, __ATOMIC_ACQUIRE));
}

uint64_t hydrogen_get_ns_since_boot(void) {
    return ns_since_boot();
}

__int128_t hydrogen_get_ns_since_epoch_utc(void) {
    return __atomic_load_n(&boot_timestamp, __ATOMIC_ACQUIRE) + ns_since_boot();
}
