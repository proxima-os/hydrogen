#pragma once

#include "fs/vfs.h"
#include "mem/vmm.h"
#include "proc/process.h"
#include <hydrogen/types.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    vmm_t *vmm;
    ident_t *ident;
    uintptr_t pc;
    uintptr_t sp;
} exec_data_t;

int create_exec_data(
    exec_data_t *out,
    process_t *process,
    file_t *image,
    ident_t *ident,
    size_t argc,
    const hydrogen_string_t *argv,
    size_t envc,
    const hydrogen_string_t *envp,
    bool user_strings
);

void exec_finalize(exec_data_t *data);
void free_exec_data(exec_data_t *data);
