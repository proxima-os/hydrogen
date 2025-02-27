#pragma once

#include "sys/elf.h"
#include "util/handle.h"
#include <stdint.h>

extern handle_data_t vdso_handle;
extern size_t vdso_size;
extern const elf_header_t vdso_image;

void init_vdso(void);

bool is_in_vdso(uintptr_t addr);
