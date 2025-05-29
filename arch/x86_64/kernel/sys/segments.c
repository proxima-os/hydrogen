#include "arch/pmap.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "x86_64/msr.h"
#include <hydrogen/x86_64/segments.h>
#include <stdint.h>

uintptr_t hydrogen_x86_64_get_fs_base(void) {
    return x86_64_rdmsr(X86_64_MSR_FS_BASE);
}

uintptr_t hydrogen_x86_64_get_gs_base(void) {
    return x86_64_rdmsr(X86_64_MSR_KERNEL_GS_BASE);
}

int hydrogen_x86_64_set_fs_base(uintptr_t value) {
    if (unlikely(!arch_pt_is_canonical(value))) return EINVAL;
    x86_64_wrmsr(X86_64_MSR_FS_BASE, value);
    return 0;
}

int hydrogen_x86_64_set_gs_base(uintptr_t value) {
    if (unlikely(!arch_pt_is_canonical(value))) return EINVAL;
    x86_64_wrmsr(X86_64_MSR_KERNEL_GS_BASE, value);
    return 0;
}
