#ifndef HYDROGEN_TIME_H
#define HYDROGEN_TIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t hydrogen_get_ns_since_boot(void);

__int128_t hydrogen_get_ns_since_epoch_utc(void);

#ifdef __cplusplus
};
#endif

#endif // HYDROGEN_TIME_H
