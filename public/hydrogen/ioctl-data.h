#ifndef HYDROGEN_IOCTL_DATA_H
#define HYDROGEN_IOCTL_DATA_H

#include <stdbool.h>
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

typedef struct {
    uint64_t start;
    uint64_t size;
} hydrogen_ioctl_mem_is_ram_t;

typedef union {
    struct {
        uint64_t address;
    } input;
    struct {
        uint64_t start;
        uint64_t size;
        bool kernel_owned;
    } output;
} hydrogen_ioctl_mem_next_ram_range_t;

typedef struct {
    uint32_t irq;
    uint32_t flags;
    bool active_low : 1;
    bool level_triggered : 1;
    bool shareable : 1;
} hydrogen_ioctl_irq_open_t;

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_IOCTL_DATA_H */
