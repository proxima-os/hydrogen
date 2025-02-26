#include "sys/usermem.h"
#include "cpu/cpu.h"
#include "hydrogen/error.h"

extern hydrogen_error_t bare_memcpy_user(void *dest, const void *src, size_t n);
extern hydrogen_error_t bare_memset_user(void *dest, int value, size_t n);
extern hydrogen_error_t smap_memcpy_user(void *dest, const void *src, size_t n);
extern hydrogen_error_t smap_memset_user(void *dest, int value, size_t n);

hydrogen_error_t (*memcpy_user)(void *dest, const void *src, size_t n);
hydrogen_error_t (*memset_user)(void *dest, int value, size_t n);

void init_usermem(void) {
    if (cpu_features.smap) {
        memcpy_user = smap_memcpy_user;
        memset_user = smap_memset_user;
    } else {
        memcpy_user = bare_memcpy_user;
        memset_user = bare_memset_user;
    }
}
