#ifndef HYDROGEN_TIME_H
#define HYDROGEN_TIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t hydrogen_get_nanoseconds_since_boot(void) __asm__("__hydrogen_get_nanoseconds_since_boot");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_TIME_H */
