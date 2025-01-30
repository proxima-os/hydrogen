#ifndef HYDROGEN_SYS_VDSO_H
#define HYDROGEN_SYS_VDSO_H

#include "mem/vmm.h"
#include <stdint.h>

extern vm_object_t vdso_object;

void init_vdso(void);

bool is_address_in_vdso(uintptr_t address);

int map_vdso(uintptr_t *addr);

#endif // HYDROGEN_SYS_VDSO_H
