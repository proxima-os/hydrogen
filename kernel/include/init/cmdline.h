#pragma once

#include "kernel/compiler.h"

typedef struct cmdline_opt {
    const char *name;
    void (*func)(const char *name, char *value);
} cmdline_opt_t;

#define CMDLINE_OPT(name, func)                                                                                     \
    __attribute__((used, section(".cmdline." name))) const cmdline_opt_t EXPAND_CONCAT(__cmdline, __COUNTER__) asm( \
            "__cmdline_" name                                                                                       \
    ) = {name, (func)}

void parse_command_line(void);
