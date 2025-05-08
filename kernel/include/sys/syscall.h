#pragma once

#include "kernel/types.h"
#include <stddef.h>
#include <stdint.h>

void do_syscall(ssize_t id, size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5);
