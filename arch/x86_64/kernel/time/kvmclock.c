#include "x86_64/kvmclock.h"
#include "kernel/x86_64/kvmclock.h"
#include "mem/memmap.h"
#include "string.h"
#include "util/printk.h"
#include "x86_64/cpu.h"
#include "x86_64/cpuid.h"
#include "x86_64/msr.h"
#include "x86_64/time.h"
#include <stdint.h>

#define KVM_FEATURE_CLOCKSOURCE (1u << 0)
#define KVM_FEATURE_CLOCKSOURCE2 (1u << 3)

static kvmclock_info_t kvmclock_info;
static uint32_t kvmclock_msr;

static uint64_t kvmclock_read(void) {
    return x86_64_read_kvmclock(&kvmclock_info);
}

static void kvmclock_cleanup(void) {
    x86_64_wrmsr(kvmclock_msr, 0);
}

void x86_64_kvmclock_init(void) {
    if (!x86_64_cpu_features.hypervisor) {
        printk("kvmclock: not running in hypervisor\n");
        return;
    }

    if (memcmp(&x86_64_cpu_features.hyp_vendor, &x86_64_cpu_vendor_kvm, sizeof(x86_64_cpu_vendor_kvm))) {
        printk("kvmclock: not running in kvm\n");
        return;
    }

    if (x86_64_cpu_features.cpuid_hyp < 0x40000001) {
        printk("kvmclock: features cpuid leaf unavailable\n");
        return;
    }

    unsigned eax, ebx, ecx, edx;
    cpuid(0x40000001, &eax, &ebx, &ecx, &edx);

    if (eax & KVM_FEATURE_CLOCKSOURCE2) {
        kvmclock_msr = X86_64_MSR_KVM_SYSTEM_TIME_NEW;
    } else if (eax & KVM_FEATURE_CLOCKSOURCE) {
        kvmclock_msr = X86_64_MSR_KVM_SYSTEM_TIME;
    } else {
        printk("kvmclock: unavailable\n");
        return;
    }

    kvmclock_info.version = 1;
    x86_64_wrmsr(kvmclock_msr, sym_to_phys(&kvmclock_info) | 1);

    x86_64_switch_timer(kvmclock_read, kvmclock_cleanup, NULL);
    printk("kvmclock: initialized\n");
}
