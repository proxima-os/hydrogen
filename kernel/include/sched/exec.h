#pragma once

#include "fs/vfs.h"

typedef struct {
    void *data;
    size_t length;
} execve_string_t;

int execve(file_t *file, execve_string_t *argv, size_t narg, execve_string_t *envp, size_t nenv);

void cleanup_execve_strings(execve_string_t *buf, size_t count);
