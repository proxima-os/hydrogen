#pragma once

static inline void cpuid(unsigned leaf, unsigned *eax, unsigned *ebx, unsigned *ecx, unsigned *edx) {
    asm("cpuid" : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx) : "a"(leaf));
}

static inline void cpuid2(unsigned leaf, unsigned subleaf, unsigned *eax, unsigned *ebx, unsigned *ecx, unsigned *edx) {
    asm("cpuid" : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx) : "a"(leaf), "c"(subleaf));
}
