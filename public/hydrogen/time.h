#ifndef HYDROGEN_TIME_H
#define HYDROGEN_TIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get the system's boot time.
 *
 * \return The number of nanoseconds that have elapsed since the system was booted.
 */
uint64_t hydrogen_boot_time(void) __asm__("__hydrogen_boot_time");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_TIME_H */
