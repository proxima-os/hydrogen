#pragma once

#include "arch/context.h"
#include <stddef.h>
#include <stdint.h>

void x86_64_idt_init(void);
_Noreturn void x86_64_idt_handle_fatal(arch_context_t *context);

// `context` must be allocated on the stack
_Noreturn void x86_64_jump_to_context(arch_context_t *context);
