#pragma once

#include "kernel/arch/vdso.h"

extern struct {
    arch_vdso_info_t arch;
} vdso_info;
