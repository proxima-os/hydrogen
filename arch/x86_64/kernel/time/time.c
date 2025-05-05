#include "arch/time.h"
#include "util/panic.h"
#include "x86_64/time.h"

static uint64_t no_time_read(void) {
    return 0;
}

static void no_time_confirm(void) {
    panic("no time source available");
}

uint64_t (*x86_64_read_time)(void) = no_time_read;
void (*x86_64_timer_cleanup)(void);
void (*x86_64_timer_confirm)(void) = no_time_confirm;

void x86_64_switch_timer(uint64_t (*read)(void), void (*cleanup)(void), void (*confirm)(void)) {
    if (x86_64_timer_cleanup) x86_64_timer_cleanup();

    x86_64_read_time = read;
    x86_64_timer_cleanup = cleanup;
    x86_64_timer_confirm = confirm;
}
