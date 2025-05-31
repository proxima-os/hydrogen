#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    size_t references;
} refcnt_t;

#define REF_INIT(count) ((refcnt_t){(count)})

static inline void ref_inc(refcnt_t *count) {
    __atomic_fetch_add(&count->references, 1, __ATOMIC_ACQUIRE);
}

static inline bool ref_dec(refcnt_t *count) {
    return __atomic_fetch_sub(&count->references, 1, __ATOMIC_ACQ_REL) == 1;
}

// Decrements the count, unless it's one, in which case true is returned.
// This is used in places where it's possible to get a reference even after the ref count drops to 0 (e.g. processes)
static inline bool ref_dec_maybe(refcnt_t *count) {
    size_t value = __atomic_load_n(&count->references, __ATOMIC_ACQUIRE);

    do {
        if (value == 1) return true;
    } while (
        !__atomic_compare_exchange_n(&count->references, &value, value - 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)
    );

    return false;
}
