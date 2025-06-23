#pragma once

#include "string.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_CPUS 64

typedef struct {
    uint64_t data;
} cpu_mask_t;

extern size_t num_cpus;

static inline bool cpu_mask_empty(cpu_mask_t *mask) {
    return mask->data == 0;
}

static inline void cpu_mask_clear(cpu_mask_t *mask) {
    mask->data = 0;
}

static inline void cpu_mask_fill(cpu_mask_t *mask) {
    mask->data = (1ull << num_cpus) - 1;
}

static inline void cpu_mask_sanitize(cpu_mask_t *mask) {
    mask->data &= (1ull << num_cpus) - 1;
}

static inline bool cpu_mask_get(const cpu_mask_t *mask, size_t cpu) {
    return mask->data & (1ull << cpu);
}

static inline bool cpu_mask_get_atomic(const cpu_mask_t *mask, size_t cpu) {
    return __atomic_load_n(&mask->data, __ATOMIC_RELAXED) & (1ull << cpu);
}

static inline void cpu_mask_set(cpu_mask_t *mask, size_t cpu, bool value) {
    if (value) mask->data |= 1ull << cpu;
    else mask->data &= ~(1ull << cpu);
}

// set a cpu's bit without tearing
// this only guarantees that the individual reads/writes are atomic,
// not that the overall operation is
static inline void cpu_mask_set_notear(cpu_mask_t *mask, size_t cpu, bool value) {
    size_t cur = __atomic_load_n(&mask->data, __ATOMIC_RELAXED);

    if (value) __atomic_store_n(&mask->data, cur | (1ull << cpu), __ATOMIC_RELAXED);
    else __atomic_store_n(&mask->data, cur & ~(1ull << cpu), __ATOMIC_RELAXED);
}

static inline void cpu_mask_set_atomic(cpu_mask_t *mask, size_t cpu, bool value, int order) {
    if (value) __atomic_fetch_or(&mask->data, 1ull << cpu, order);
    else __atomic_fetch_and(&mask->data, 1ull << cpu, order);
}

// copies the cpu mask using atomic loads
static inline void cpu_mask_copy_atomic(cpu_mask_t *dest, const cpu_mask_t *src) {
    dest->data = __atomic_load_n(&src->data, __ATOMIC_ACQUIRE);
}
