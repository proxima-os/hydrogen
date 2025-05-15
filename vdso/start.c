#include "hydrogen/process.h"
#include <stdint.h>

_Noreturn void vdso_start(void) {
    hydrogen_process_exit(0);
}
