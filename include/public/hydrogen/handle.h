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
 * Create an empty namespace.
 *
 * \return The newly created namespace (in `handle`).
 */
hydrogen_ret_t hydrogen_namespace_create(void) __asm__("__hydrogen_namespace_create");

/**
 * Create a new handle in a namespace.
 *
 * \param[in] ns The namespace to create the handle in. If `NULL`, use the current namespace.
 *               Requires the #HYDROGEN_NAMESPACE_RIGHT_CREATE right.
 * \param[in] object The object the handle will reference. Must not be a namespace.
 * \param[in] rights The rights of the newly created handle. Masked with the rights of `object`.
 * \return The newly created handle (in `handle`).
 */
hydrogen_ret_t hydrogen_handle_create(hydrogen_handle_t ns, hydrogen_handle_t object, uint64_t rights) __asm__(
        "__hydrogen_handle_create"
);

/**
 * Close a handle.
 *
 * \param[in] ns The namespace the handle is in. If `NULL`, use the current namespace.
 *               Requires the #HYDROGEN_NAMESPACE_RIGHT_CLOSE right.
 * \param[in] handle The handle to close.
 * \return The only error this function can return is `EBADF`.
 */
int hydrogen_handle_close(hydrogen_handle_t ns, hydrogen_handle_t handle) __asm__("__hydrogen_handle_close");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_HANDLE_H */
