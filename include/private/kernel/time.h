#pragma once

#include <stdint.h>

typedef struct {
    uint64_t multiplier;
    unsigned shift;
} timeconv_t;

static inline uint64_t timeconv_apply(timeconv_t conv, uint64_t value) {
    return ((__uint128_t)value * conv.multiplier) >> conv.shift;
}
