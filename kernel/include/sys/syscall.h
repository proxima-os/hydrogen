#pragma once

#include "kernel/types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool prepare_syscall(uintptr_t pc);
void do_syscall(ssize_t id, size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5);

int verify_user_buffer(uintptr_t start, size_t size);
