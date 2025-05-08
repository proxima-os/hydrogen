#include "sys/transition.h"
#include "cpu/cpudata.h"
#include "kernel/compiler.h"
#include "x86_64/cpu.h"
#include "x86_64/xsave.h"
#include <stddef.h>
#include <stdint.h>

_Noreturn void x86_64_enter_user_mode(size_t rip, size_t cs, size_t rflags, size_t rsp, size_t ss);

_Noreturn void arch_enter_user_mode(uintptr_t pc, uintptr_t stack_base, size_t stack_size) {
    ASSERT(current_thread->arch.xsave != NULL);
    x86_64_xsave_reset(current_thread->arch.xsave);
    x86_64_enter_user_mode(pc, X86_64_USER_CS, 0x200, stack_base + stack_size, X86_64_USER_DS);
}
