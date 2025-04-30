#ifndef HYDROGEN_TIME_H
#define HYDROGEN_TIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get the number of nanoseconds that have elapsed since the system started.
 *
 * \return The number of nanoseconds that have elapsed since boot.
 */
uint64_t hydrogen_get_time(void) __asm__("__hydrogen_get_time");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_TIME_H */
