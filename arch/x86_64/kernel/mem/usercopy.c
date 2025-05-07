#include "mem/usercopy.h"
#include "kernel/compiler.h"
#include <stdint.h>

bool arch_is_user_copy(uintptr_t pc) {
    extern const void x86_64_usercopy_start, x86_64_usercopy_end;
    return (uintptr_t)&x86_64_usercopy_start <= pc && pc < (uintptr_t)&x86_64_usercopy_end;
}

void arch_user_copy_fail(arch_context_t *context, int error) {
    ASSERT(arch_is_user_copy(context->rip));
    context->rcx = 0;
    context->rdx = error;
}
