#pragma once

#include <stddef.h>

extern size_t x86_64_xsave_size;

void x86_64_xsave_init_local(void);

// allocates an xsave area containing the current xsave state
void *x86_64_xsave_alloc(void);
void x86_64_xsave_free(void *area);

void x86_64_xsave_reinit(void *area);
void x86_64_xsave_sanitize(void *area);

void x86_64_xsave_save(void *area);
void x86_64_xsave_restore(void *area);

void x86_64_xsave_reset(void *area);
