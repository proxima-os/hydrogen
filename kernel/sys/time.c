#include "hydrogen/time.h"
#include "arch/time.h"

uint64_t hydrogen_get_nanoseconds_since_boot(void) {
    return arch_read_time();
}
