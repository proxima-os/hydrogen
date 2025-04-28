#ifndef HYDROGEN_THREAD_H
#define HYDROGEN_THREAD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Exit the current thread.
 */
__attribute__((__noreturn__)) void hydrogen_thread_exit(void) asm("__hydrogen_thread_exit");

#ifdef __x86_64__
/**
 * Get the current base address of the `fs` segment.
 *
 * \return The base address of the `fs` segment.
 */
uintptr_t hydrogen_x86_64_get_fs_base(void);

/**
 * Get the current base address of the `gs` segment.
 *
 * \return The base address of the `gs` segment.
 */
uintptr_t hydrogen_x86_64_get_gs_base(void);

/**
 * Set the base address of the `fs` segment.
 *
 * \param[in] address The new base address of the segment.
 */
int hydrogen_x86_64_set_fs_base(uintptr_t address);

/**
 * Set the base address of the `gs` segment.
 *
 * \param[in] address The new base address of the segment.
 */
int hydrogen_x86_64_set_gs_base(uintptr_t address);
#endif /* defined(__x86_64__) */

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_THREAD_H */
