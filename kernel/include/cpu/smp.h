#pragma once

#include "cpu/cpudata.h"

/* if `dest` is NULL, broadcast. `func` runs in IRQ context. */
void smp_call_remote(cpu_t *dest, void (*func)(void *), void *ctx);
void smp_call_remote_async(cpu_t *dest, void (*func)(void *), void *ctx);
