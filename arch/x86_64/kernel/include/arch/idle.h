#pragma once

static inline void cpu_idle(void) {
    asm("hlt");
}

static inline void cpu_relax(void) {
    __builtin_ia32_pause();
}
