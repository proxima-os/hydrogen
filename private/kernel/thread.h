#pragma once

#include "hydrogen/types.h"
#include <stddef.h>

typedef struct {
    const hydrogen_string_t *argv, *envp;
    size_t argc, envc;
} exec_syscall_args_t;
