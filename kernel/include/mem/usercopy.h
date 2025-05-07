#pragma once

#include "arch/context.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool arch_is_user_copy(uintptr_t pc);
void arch_user_copy_fail(arch_context_t *context, int error);

int user_memcpy(void *dest, const void *src, size_t count);
int user_memset(void *dest, int value, size_t count);
