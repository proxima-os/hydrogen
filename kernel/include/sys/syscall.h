#pragma once

#include "hydrogen/error.h"
#include <stddef.h>
#include <stdint.h>

void init_syscall(void);
void init_syscall_cpu(void);

_Noreturn void enter_user_mode(uintptr_t rip, uintptr_t rsp);

hydrogen_error_t verify_user_pointer(const void *ptr, size_t size);
