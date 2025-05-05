#include "cpu/smp.h"
#include "arch/idle.h"
#include "arch/smp.h"
#include "cpu/cpudata.h"
#include "kernel/compiler.h"
#include "util/slist.h"

static smp_call_id_t next = 1;

void smp_call_remote(cpu_t *dest, void (*func)(void *), void *ctx) {
    smp_call_wait(dest, smp_call_remote_async(dest, func, ctx));
}

static void trigger_call(cpu_t *cpu, smp_call_id_t id, void (*func)(void *), void *ctx) {
    smp_call_id_t wanted = 0;
    while (!__atomic_compare_exchange_n(
            &cpu->remote_call.current,
            &wanted,
            id,
            true,
            __ATOMIC_ACQUIRE,
            __ATOMIC_RELAXED
    )) {
        cpu_relax();
        wanted = 0;
    }

    cpu->remote_call.func = func;
    cpu->remote_call.ctx = ctx;
    arch_remote_call(cpu);
}

smp_call_id_t smp_call_remote_async(cpu_t *dest, void (*func)(void *), void *ctx) {
    smp_call_id_t id = __atomic_fetch_add(&next, 1, __ATOMIC_ACQ_REL);

    if (dest) {
        ASSERT(dest != get_current_cpu());
        trigger_call(dest, id, func, ctx);
    } else {
        cpu_t *cur = get_current_cpu();

        SLIST_FOREACH(cpus, cpu_t, node, cpu) {
            if (cpu != cur) {
                trigger_call(cpu, id, func, ctx);
            }
        }
    }

    return id;
}

void smp_call_wait(cpu_t *dest, smp_call_id_t id) {
again:
    if (dest) {
        smp_call_id_t current = __atomic_load_n(&dest->remote_call.current, __ATOMIC_ACQUIRE);
        if (current != 0 && current < id) goto again;
    } else {
        cpu_t *cur = get_current_cpu();

        SLIST_FOREACH(cpus, cpu_t, node, cpu) {
            if (cur != cpu) {
                smp_call_id_t current = __atomic_load_n(&cpu->remote_call.current, __ATOMIC_ACQUIRE);
                if (current != 0 && current < id) goto again;
            }
        }
    }
}

void smp_handle_remote_call(void) {
    cpu_t *cpu = get_current_cpu();
    cpu->remote_call.func(cpu->remote_call.ctx);
    __atomic_store_n(&cpu->remote_call.current, 0, __ATOMIC_RELEASE);
}
