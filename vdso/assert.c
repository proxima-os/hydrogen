#include "kernel/compiler.h"

_Noreturn void hydrogen_assert_fail(const char *expr, const char *func, const char *file, int line) {
    __builtin_trap();
}
