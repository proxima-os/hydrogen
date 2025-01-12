#ifndef HYDROGEN_TIME_H
#define HYDROGEN_TIME_H

#include <stdint.h>

uint64_t hydrogen_get_ns_since_boot(void);

__int128_t hydrogen_get_ns_since_epoch_utc(void);

#endif // HYDROGEN_TIME_H
