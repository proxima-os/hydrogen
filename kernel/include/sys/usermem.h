#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uintptr_t start;
    uintptr_t end;
    uintptr_t ret;
} usermem_funcs_t;

extern const usermem_funcs_t usermem_funcs;
extern int (*memcpy_user)(void *dest, const void *src, size_t n);
extern int (*memset_user)(void *dest, int value, size_t n);

void init_usermem(void);
