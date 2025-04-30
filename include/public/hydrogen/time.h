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

/**
 * Suspend the current thread until the system time has reached `deadline`.
 *
 * \param[in] deadline The system time at which the thread should wake up.
 * \return The only error this function can return is `EINTR`.
 */
int hydrogen_sleep(uint64_t deadline) __asm__("__hydrogen_sleep");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_TIME_H */
