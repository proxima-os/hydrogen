/** \file
 * Definitions for handle management.
 */

#ifndef HYDROGEN_HANDLE_H
#define HYDROGEN_HANDLE_H

#include "error.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A reference to a kernel object.
 *
 * Besides indicating which object to operate on, a handle also specifies its "rights": what operations are allowed on
 * the object.
 *
 * Handles are local to namespaces. Every thread has an implicit namespace handle with create and close rights.
 * To prevent circular references, the only way to get an explicit handle to a namespace is to create one - in other
 * words, namespace handles cannot be transferred across namespace boundaries.
 */
typedef const void *hydrogen_handle_t;

#define HYDROGEN_NAMESPACE_RIGHT_CREATE (1ull << 0) /**< Allow handles to be created in the namespace. */
#define HYDROGEN_NAMESPACE_RIGHT_CLOSE (1ull << 1)  /**< Allow handles to be closed in the namespace. */

/**
 * Creates an empty namespace.
 *
 * @param[out] ns The newly created namespace.
 */
hydrogen_error_t hydrogen_namespace_create(hydrogen_handle_t *ns);

/**
 * Creates a new handle in a namespace.
 *
 * \param[in] ns The namespace to create the handle in. If `NULL`, use the current namespace.
 *               Requires the #HYDROGEN_NAMESPACE_CREATE right.
 * \param[in] object The object the handle will reference. Must not be the specified namespace.
 * \param[in] rights The rights of the newly created handle. Masked with the rights of `object`.
 * \param[out] handle The newly created handle.
 */
hydrogen_error_t hydrogen_handle_create(
        hydrogen_handle_t ns,
        hydrogen_handle_t object,
        uint64_t rights,
        hydrogen_handle_t *handle
);

/**
 * Closes a handle.
 *
 * \param[in] ns The namespace the handle is in. If `NULL`, use the current namespace.
 *               Requires the #HYDROGEN_NAMESPACE_CLOSE right.
 * \param[in] handle The handle to close.
 * \return The only errors that this function can encounter are #HYDROGEN_INVALID_HANDLE and #HYDROGEN_NO_PERMISSION.
 */
hydrogen_error_t hydrogen_handle_close(hydrogen_handle_t ns, hydrogen_handle_t handle);

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_HANDLE_H */
