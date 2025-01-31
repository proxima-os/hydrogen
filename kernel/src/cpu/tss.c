#include "cpu/tss.h"
#include "cpu/cpu.h"
#include "util/panic.h"

void init_tss(void) {
    current_cpu.tss.iopb_offset = sizeof(current_cpu.tss);
    ASSERT(current_cpu.tss.ist[0] != 0);
}
