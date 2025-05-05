#include "arch/time.h"

static uint64_t no_read_time(void) {
    return 0;
}

uint64_t (*x86_64_read_time)(void) = no_read_time;
