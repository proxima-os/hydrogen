#ifndef HYDROGEN_HYDROGEN_H
#define HYDROGEN_HYDROGEN_H

#include <hydrogen/types.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get the name of the kernel.
 *
 * \param[out] buffer The buffer to write the kernel name in to.
 * \param[in] size The size of the buffer.
 * \return The size of the buffer necessary to hold the full kernel name.
 *         Note that this may be larger than the `size` parameter.
 */
size_t hydrogen_get_kernel_name(void *buffer, size_t size) __asm__("__hydrogen_get_kernel_name");

/**
 * Get the release of the kernel.
 *
 * \param[out] buffer The buffer to write the kernel release in to.
 * \param[in] size The size of the buffer.
 * \return The size of the buffer necessary to hold the full kernel release.
 *         Note that this may be larger than the `size` parameter.
 */
size_t hydrogen_get_kernel_release(void *buffer, size_t size) __asm__("__hydrogen_get_kernel_release");

/**
 * Get the version of the kernel.
 *
 * \param[out] buffer The buffer to write the kernel version in to.
 * \param[in] size The size of the buffer.
 * \return The size of the buffer necessary to hold the full kernel version.
 *         Note that this may be larger than the `size` parameter.
 */
size_t hydrogen_get_kernel_version(void *buffer, size_t size) __asm__("__hydrogen_get_kernel_version");

/**
 * Get the host name of the system.
 *
 * \param[out] buffer The buffer to write the host name in to.
 * \param[in] size The size of the buffer.
 * \return The size of the buffer necessary to hold the full host name (in `integer`).
 *         Note that this may be larger than the `size` parameter.
 */
hydrogen_ret_t hydrogen_get_host_name(void *buffer, size_t size) __asm__("__hydrogen_get_host_name");

/**
 * Set the host name of the system.
 *
 * \param[in] name The new host name.
 * \param[in] size The size of the new host name.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_set_host_name(const void *name, size_t size) __asm__("__hydrogen_set_host_name");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_HYDROGEN_H */
