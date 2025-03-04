#pragma once

#include <stddef.h>
#include <stdint.h>

void init_syscall(void);
void init_syscall_cpu(void);

_Noreturn void enter_user_mode(uintptr_t rip, uintptr_t rsp);

int verify_user_pointer(const void *ptr, size_t size);
