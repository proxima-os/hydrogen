#pragma once

#include <stddef.h>
#include <stdint.h>

static inline uint32_t make_hash_i32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7feb352d;
    x ^= x >> 15;
    x *= 0x846ca68b;
    x ^= x >> 16;
    return x;
}

static inline uint64_t make_hash_i64(uint64_t x) {
    x *= 0xe9770214b82cf957;
    x ^= x >> 47;
    x *= 0x2bdd9d20d060fc9b;
    x ^= x >> 44;
    x *= 0x65c487023b406173;
    return x;
}

static inline uintptr_t make_hash_iptr(uintptr_t x) {
#if UINTPTR_MAX == UINT64_MAX
    return make_hash_i64(x);
#elif UINTPTR_MAX == UINT32_MAX
    return make_hash_i32(x);
#else
#error "Unsupported address width"
#endif
}

// FNV-1a
static inline uint64_t make_hash_blob(const void *data, size_t size) {
    uint64_t hash = 0xcbf29ce484222325;

    while (size--) {
        hash ^= *(const unsigned char *)data++;
        hash *= 0x100000001b3;
    }

    return hash;
}
