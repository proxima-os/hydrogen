#pragma once

#include "mem/vmm.h"
#include "sys/elf.h"
#include <stddef.h>

extern mem_object_t vdso_object;
extern size_t vdso_image_offset;
extern size_t vdso_size;
extern elf_header_t vdso_image;

void vdso_init(void);
