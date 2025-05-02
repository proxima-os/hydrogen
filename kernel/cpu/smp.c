#include "cpu/smp.h"
#include "util/panic.h"

void smp_call_remote(cpu_t *dest, void (*func)(void *), void *ctx) {
    if (dest) panic("TODO: smp_call_remote");
}

void smp_call_remote_async(cpu_t *dest, void (*func)(void *), void *ctx) {
    if (dest) panic("TODO: smp_call_remote_async");
}
