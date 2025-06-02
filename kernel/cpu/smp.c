#include "cpu/smp.h"
#include "arch/smp.h"
#include "cpu/cpudata.h"
#include "kernel/compiler.h"
#include "proc/sched.h"
#include "util/slist.h"

void smp_call_remote(cpu_t *dest, smp_remote_call_type_t type) {
    migrate_state_t state = migrate_lock();

    if (dest) {
        ASSERT(dest != get_current_cpu());
        arch_remote_call(dest, type);
    } else {
        cpu_t *cur = get_current_cpu();

        SLIST_FOREACH(cpus, cpu_t, node, cpu) {
            if (cpu != cur) {
                arch_remote_call(cpu, type);
            }
        }
    }

    migrate_unlock(state);
}
