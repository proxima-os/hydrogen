#include "hydrogen/time.h"
#include "arch/syscall.h"
#include "kernel/syscall.h"
#include "vdso.h"
#include <stdint.h>

EXPORT int hydrogen_set_real_time(__int128_t time) {
    uint64_t low = time;
    uint64_t high = time >> 64;
    return SYSCALL2(SYSCALL_SET_REAL_TIME, low, high).error;
}
