/** \file
 * Definitions for segmentation.
 */
#ifndef HYDROGEN_X86_64_SEGMENTS_H
#define HYDROGEN_X86_64_SEGMENTS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get the base address of the fs segment.
 *
 * \return The base address of the fs segment.
 */
uintptr_t hydrogen_x86_64_get_fs_base(void) __asm__("__hydrogen_x86_64_get_fs_base");

/**
 * Get the base address of the gs segment.
 *
 * \return The base address of the gs segment.
 */
uintptr_t hydrogen_x86_64_get_gs_base(void) __asm__("__hydrogen_x86_64_get_gs_base");

/**
 * Set the base address of the fs segment.
 *
 * \param[in] value The base address of the fs segment.
 * \return 0, if successful; if not, an error code. Can only return an error if `value` is not canonical.
 */
int hydrogen_x86_64_set_fs_base(uintptr_t value) __asm__("__hydrogen_x86_64_set_fs_base");

/**
 * Set the base address of the gs segment.
 *
 * \param[in] value The base address of the gs segment.
 * \return 0, if successful; if not, an error code. Can only return an error if `value` is not canonical.
 */
int hydrogen_x86_64_set_gs_base(uintptr_t value) __asm__("__hydrogen_x86_64_set_gs_base");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_X86_64_SEGMENTS_H */
