#ifndef HYDROGEN_TIME_H
#define HYDROGEN_TIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns the number of nanoseconds that have elapsed since some point in the past.
 */
uint64_t hydrogen_get_time(void);

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_TIME_H */
