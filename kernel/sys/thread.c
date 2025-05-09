#include "hydrogen/thread.h"
#include "proc/sched.h"

void hydrogen_thread_yield(void) {
    sched_yield();
}

_Noreturn void hydrogen_thread_exit(int status) {
    sched_exit();
}
