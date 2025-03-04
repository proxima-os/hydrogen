#include "sys/usermem.h"
#include "cpu/cpu.h"

extern int bare_memcpy_user(void *dest, const void *src, size_t n);
extern int bare_memset_user(void *dest, int value, size_t n);
extern int smap_memcpy_user(void *dest, const void *src, size_t n);
extern int smap_memset_user(void *dest, int value, size_t n);

int (*memcpy_user)(void *dest, const void *src, size_t n);
int (*memset_user)(void *dest, int value, size_t n);

void init_usermem(void) {
    if (cpu_features.smap) {
        memcpy_user = smap_memcpy_user;
        memset_user = smap_memset_user;
    } else {
        memcpy_user = bare_memcpy_user;
        memset_user = bare_memset_user;
    }
}
