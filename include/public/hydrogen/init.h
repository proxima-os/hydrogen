#ifndef HYDROGEN_INIT_H
#define HYDROGEN_INIT_H

#include "hydrogen/handle.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HYDROGEN_INIT_INFO_MAJOR_VERSION 0 /**< The current init info major version. */
#define HYDROGEN_INIT_INFO_MINOR_VERSION 0 /**< The current init info minor version. */

/**
 * Information passed to the init process by the kernel upon boot.
 * This struct is versioned. As long as the major version remains the same, newer minor versions are backwards
 * compatible with older ones. However, if the major version changes, only `major`, `minor`, `vdso_base`,
 * `command_line`, and `log_handle` are guaranteed to be in the same location with the same meaning.
 */
typedef struct {
    int major;                    /**< The major version of the init info. */
    int minor;                    /**< The minor version of the init info. */
    const void *vdso_base;        /**< Base of the vDSO */
    char *command_line;           /**< Command line passed to the init image. */
    hydrogen_handle_t log_handle; /**< Handle to the kernel log. */
    hydrogen_handle_t ram_handle; /**< Handle to physical memory. */
    hydrogen_handle_t io_handle;  /**< Handle representing permission to enable I/O port access. */
    uint64_t rsdp;                /**< Physical address of the ACPI RSDP. -1 if not available. */
} hydrogen_init_info_t;

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_INIT_H */
