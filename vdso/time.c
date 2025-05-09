#include "hydrogen/time.h"
#include "arch/syscall.h"
#include "kernel/syscall.h"
#include "vdso.h"
#include <stdint.h>

EXPORT int hydrogen_set_real_time(int64_t time) {
    return SYSCALL1(SYSCALL_SET_REAL_TIME, time).error;
}
