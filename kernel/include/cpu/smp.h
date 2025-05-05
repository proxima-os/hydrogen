#pragma once

#include <stddef.h>

struct cpu;

typedef size_t smp_call_id_t;

/* if `dest` is NULL, broadcast. `func` runs in IRQ context. */
void smp_call_remote(struct cpu *dest, void (*func)(void *), void *ctx);
smp_call_id_t smp_call_remote_async(struct cpu *dest, void (*func)(void *), void *ctx);
void smp_call_wait(struct cpu *dest, smp_call_id_t id);

/* this function is internal */
void smp_handle_remote_call(void);
