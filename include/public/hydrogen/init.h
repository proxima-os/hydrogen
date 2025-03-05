#ifndef HYDROGEN_INIT_H
#define HYDROGEN_INIT_H

#include "hydrogen/handle.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HYDROGEN_INIT_INFO_MAJOR_VERSION 0 /**< The current init info major version. */
#define HYDROGEN_INIT_INFO_MINOR_VERSION 0 /**< The current init info minor version. */

#define HYDROGEN_AT_INIT_INFO 0x80000000ul

/**
 * Information passed to the init process by the kernel upon boot.
 * This struct is versioned. As long as the major version remains the same, newer minor versions are backwards
 * compatible with older ones. However, if the major version changes, only `major`, `minor`, and `log_handle`
 * are guaranteed to be in the same location with the same meaning.
 */
typedef struct {
    int major;                    /**< The major version of the init info. */
    int minor;                    /**< The minor version of the init info. */
    hydrogen_handle_t log_handle; /**< Handle to the kernel log. */
    hydrogen_handle_t ram_handle; /**< Handle to physical memory. */
    hydrogen_handle_t io_handle;  /**< Handle to the I/O address space. */
    uint64_t rsdp;                /**< Physical address of the ACPI RSDP. -1 if not available. */
} hydrogen_init_info_t;

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_INIT_H */
