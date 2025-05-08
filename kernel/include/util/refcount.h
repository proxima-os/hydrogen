#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    size_t references;
} refcnt_t;

#define REF_INIT(count) ((refcnt_t){(count)})

static inline void ref_add(refcnt_t *count, size_t num) {
    __atomic_fetch_add(&count->references, num, __ATOMIC_ACQUIRE);
}

static inline bool ref_sub(refcnt_t *count, size_t num) {
    return __atomic_fetch_sub(&count->references, num, __ATOMIC_ACQ_REL) == num;
}

static inline void ref_inc(refcnt_t *count) {
    ref_add(count, 1);
}

static inline bool ref_dec(refcnt_t *count) {
    return ref_sub(count, 1);
}
