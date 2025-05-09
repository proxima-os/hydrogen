#include "hydrogen/time.h"
#include "arch/time.h"

uint64_t hydrogen_boot_time(void) {
    return arch_read_time();
}
