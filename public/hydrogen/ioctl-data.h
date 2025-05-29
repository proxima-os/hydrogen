#ifndef HYDROGEN_IOCTL_DATA_H
#define HYDROGEN_IOCTL_DATA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union {
    struct {
        uint64_t min;
        uint64_t max;
        uint64_t size;
        uint64_t align; /**< Must be a power of two. */
        int flags;
    } input;
    struct {
        uint64_t address;
    } output;
} hydrogen_ioctl_mem_allocate_t;

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_IOCTL_DATA_H */
