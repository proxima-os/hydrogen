#pragma once

#include "arch/context.h"
#include <stddef.h>
#include <stdint.h>

void enter_from_user_mode(arch_context_t *context);
void exit_to_user_mode(void);

_Noreturn void arch_enter_user_mode(uintptr_t pc, uintptr_t stack_base, size_t stack_size);
