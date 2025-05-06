#include "x86_64/mca.h"
#include "sections.h"
#include "x86_64/cpu.h"
#include "x86_64/cr.h"
#include "x86_64/msr.h"
#include <stdint.h>

INIT_TEXT void x86_64_mca_init(void) {
    if (!x86_64_cpu_features.mce) return;

    if (x86_64_cpu_features.mca) {
        uint64_t cap = x86_64_rdmsr(X86_64_MSR_MCG_CAP);

        if (cap & X86_64_MSR_MCG_CAP_MCG_CTL_P) {
            x86_64_wrmsr(X86_64_MSR_MCG_CTL, UINT64_MAX);
        }

        int banks = cap & X86_64_MSR_MSG_CAP_COUNT;

        for (int i = 0; i < banks; i++) {
            x86_64_wrmsr(X86_64_MSR_MCi_CTL(i), UINT64_MAX);
            x86_64_wrmsr(X86_64_MSR_MCi_STATUS(i), 0);
        }
    }

    x86_64_write_cr4(x86_64_read_cr4() | X86_64_CR4_MCE);
}
