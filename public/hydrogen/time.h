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

/**
 * Get the current real time.
 *
 * \return The number of nanoseconds that have elapsed since 1970-01-01T00:00:00Z.
 */
int64_t hydrogen_get_real_time(void) __asm__("__hydrogen_get_real_time");

/**
 * Set the current real time.
 *
 * This operation requires root.
 *
 * \param[in] time The number of nanoseconds that have elapsed since 1970-01-01T00:00:00Z.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_set_real_time(int64_t time) __asm__("__hydrogen_set_real_time");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_TIME_H */
