#include "cpu/tss.h"
#include "cpu/cpu.h"

void init_tss(void) {
    current_cpu.tss.iopb_offset = sizeof(current_cpu.tss);
}
