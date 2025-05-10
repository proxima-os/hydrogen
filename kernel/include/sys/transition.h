#pragma once

#include "arch/context.h"
#include "hydrogen/signal.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void enter_from_user_mode(arch_context_t *context);
void exit_to_user_mode(int syscall_status); // syscall_status is -1 if this isn't due to a syscall

_Noreturn void arch_enter_user_mode(uintptr_t pc, uintptr_t sp);
_Noreturn void arch_enter_user_mode_init(uintptr_t pc, uintptr_t stack_base, size_t stack_size);

// `context` must be allocated on the stack
_Noreturn void arch_enter_user_mode_context(arch_context_t *context);

int arch_setup_context_for_signal(struct __sigaction *handler, __siginfo_t *info, __stack_t *stack);
