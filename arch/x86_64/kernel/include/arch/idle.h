#pragma once

static inline void cpu_idle(void) {
    asm("hlt");
}
