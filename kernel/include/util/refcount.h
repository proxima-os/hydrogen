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
