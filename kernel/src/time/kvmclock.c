#include "time/kvmclock.h"
#include "asm/cpuid.h"
#include "asm/msr.h"
#include "cpu/cpu.h"
#include "kernel/kvmclock.h"
#include "kernel/vdso.h"
#include "mem/pmm.h"
#include "string.h"
#include "time/time.h"
#include "util/logging.h"
#include <stdint.h>

static uint64_t do_read_kvmclock(void) {
    return kvmclock_read(&vdso_info.time.kvmclock);
}

void init_kvmclock(void) {
    if (cpu_features.hypervisor.max_leaf < 0x40000001) return;
    if (memcmp(&cpu_features.hypervisor.vendor, &HYPERVISOR_SIG_KVM, sizeof(HYPERVISOR_SIG_KVM))) return;

    uint32_t eax, ebx, ecx, edx;
    cpuid(0x40000001, &eax, &ebx, &ecx, &edx);

    uint64_t msr;

    if (eax & (1u << 3)) {
        msr = MSR_KVM_SYSTEM_TIME_NEW;
    } else if (eax & (1u << 0)) {
        msr = MSR_KVM_SYSTEM_TIME;
    } else {
        return;
    }

    vdso_info.time.kvmclock.version = 1;
    wrmsr(msr, sym_to_phys(&vdso_info.time.kvmclock) | 1);

    if (timer_cleanup) timer_cleanup();

    read_time = do_read_kvmclock;
    read_time_unlocked = do_read_kvmclock;
    timer_cleanup = NULL;

    vdso_info.time.style = VDSO_TIME_KVMCLOCK;
    printk("time: kvmclock is available\n");
}
