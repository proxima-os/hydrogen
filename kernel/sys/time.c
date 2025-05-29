#include "arch/time.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "proc/process.h"
#include "util/time.h"
#include <hydrogen/time.h>
#include <stdint.h>

uint64_t hydrogen_boot_time(void) {
    return arch_read_time();
}

__int128_t hydrogen_get_real_time(void) {
    return get_current_timestamp();
}

int hydrogen_set_real_time(__int128_t time) {
    if (unlikely(getuid(current_thread->process) != 0)) return EPERM;

    set_current_timestamp(time);
    return 0;
}
