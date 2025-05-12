#include "hydrogen/thread.h"
#include <stdint.h>

_Noreturn void vdso_start(void) {
    hydrogen_thread_exit(0);
}
