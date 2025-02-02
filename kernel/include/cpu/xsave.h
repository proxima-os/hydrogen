#pragma once

void init_xsave(void);

void *xsave_alloc(void);
void xsave_free(void *ptr);

void xsave(void);
void xrestore(void);
void xreset(void);
