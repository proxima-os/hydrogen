#include "time/kvmclock.h"
#include "asm/cpuid.h"
#include "asm/msr.h"
#include "cpu/cpu.h"
#include "kernel/compiler.h"
#include "kernel/kvmclock.h"
#include "mem/kmalloc.h"
#include "mem/pmm.h"
#include "string.h"
#include "time/time.h"
#include "util/logging.h"
#include <stdint.h>

static kvmclock_info_t *kvmclock_info;

static uint64_t do_read_kvmclock(void) {
    return kvmclock_read(kvmclock_info);
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

    kvmclock_info = kmalloc(sizeof(*kvmclock_info));
    if (unlikely(!kvmclock_info)) {
        printk("time: failed to allocate kvmclock info\n");
        return;
    }
    memset(kvmclock_info, 0, sizeof(*kvmclock_info));
    kvmclock_info->version = 1;
    wrmsr(msr, virt_to_phys(kvmclock_info) | 1);

    read_time = do_read_kvmclock;
    read_time_unlocked = do_read_kvmclock;

    printk("time: kvmclock is available\n");
    use_short_calibration();
}
