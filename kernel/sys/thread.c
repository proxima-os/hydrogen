#include "hydrogen/thread.h"
#include "proc/sched.h"

_Noreturn void hydrogen_thread_exit(int status) {
    sched_exit();
}
