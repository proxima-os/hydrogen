#include "mem/usercopy.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "sections.h"
#include "x86_64/cpu.h"
#include <stdint.h>

int (*user_memcpy)(void *dest, const void *src, size_t count);
int (*user_memset)(void *dest, int value, size_t count);

extern int x86_64_user_memcpy_regular(void *dest, const void *src, size_t count);
extern int x86_64_user_memset_regular(void *dest, int value, size_t count);

extern int x86_64_user_memcpy_smap(void *dest, const void *src, size_t count);
extern int x86_64_user_memset_smap(void *dest, int value, size_t count);

static void init_usercopy(void) {
    if (x86_64_cpu_features.smap) {
        user_memcpy = x86_64_user_memcpy_smap;
        user_memset = x86_64_user_memset_smap;
    } else {
        user_memcpy = x86_64_user_memcpy_regular;
        user_memset = x86_64_user_memset_regular;
    }
}

INIT_DEFINE_EARLY(x86_64_usercopy, init_usercopy);

bool arch_is_user_copy(uintptr_t pc) {
    extern const void x86_64_usercopy_start, x86_64_usercopy_end;
    return (uintptr_t)&x86_64_usercopy_start <= pc && pc < (uintptr_t)&x86_64_usercopy_end;
}

void arch_user_copy_fail(arch_context_t *context, int error) {
    ASSERT(arch_is_user_copy(context->rip));
    context->rcx = 0;
    context->rdx = error;
}
