/** \file
 * Definitions for handle management.
 */

#ifndef HYDROGEN_HANDLE_H
#define HYDROGEN_HANDLE_H

#include "hydrogen/types.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HYDROGEN_NAMESPACE_RIGHT_CREATE (1ull << 0) /**< Allow handles to be created in the namespace. */
#define HYDROGEN_NAMESPACE_RIGHT_CLOSE (1ull << 1)  /**< Allow handles to be closed in the namespace. */

/**
 * Creates an empty namespace.
 *
 * @param[out] ns The newly created namespace.
 */
hydrogen_ret_t hydrogen_namespace_create(void) __asm__("__hydrogen_namespace_create");

/**
 * Creates a new handle in a namespace.
 *
 * \param[in] ns The namespace to create the handle in. If `NULL`, use the current namespace.
 *               Requires the #HYDROGEN_NAMESPACE_CREATE right.
 * \param[in] object The object the handle will reference. Must not be the specified namespace.
 * \param[in] rights The rights of the newly created handle. Masked with the rights of `object`.
 * \param[out] handle The newly created handle.
 */
hydrogen_ret_t hydrogen_handle_create(hydrogen_handle_t ns, hydrogen_handle_t object, uint64_t rights) __asm__(
        "__hydrogen_handle_create"
);

/**
 * Closes a handle.
 *
 * \param[in] ns The namespace the handle is in. If `NULL`, use the current namespace.
 *               Requires the #HYDROGEN_NAMESPACE_CLOSE right.
 * \param[in] handle The handle to close.
 * \return The only errors that this function can encounter are #HYDROGEN_INVALID_HANDLE and #HYDROGEN_NO_PERMISSION.
 */
int hydrogen_handle_close(hydrogen_handle_t ns, hydrogen_handle_t handle) __asm__("__hydrogen_handle_close");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_HANDLE_H */
