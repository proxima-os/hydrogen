#pragma once

static inline void arch_cpu_idle(void) {
    asm("hlt");
}
