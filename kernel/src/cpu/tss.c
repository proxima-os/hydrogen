#include "cpu/tss.h"
#include "cpu/cpu.h"
#include "util/panic.h"

void init_tss(void) {
    current_cpu.tss.iopb_offset = sizeof(current_cpu.tss);

    ASSERT(current_cpu.tss.ist[0] != 0);

    // ensure paranoid entry code works correctly
    for (int i = 0; i < 7; i++) {
        uintptr_t ist = current_cpu.tss.ist[i];
        if (ist == 0) continue;

        ist -= 16;
        *(void **)ist = current_cpu_ptr;
        current_cpu.tss.ist[i] = ist;
    }
}
