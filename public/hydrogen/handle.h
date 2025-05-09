/** \file
 * Definitions for handle management.
 *
 * Handles are, effectively, pointers to kernel objects. Each handle also has flags that affect some aspects of system
 * behavior, as well as a rights bitmask that specifies what operations are allowed using the handle.
 *
 * # Handle allocation
 * All functions that create handles, with the exception of #hydrogen_namespace_add, return the lowest
 * free handle.
 */

#ifndef HYDROGEN_HANDLE_H
#define HYDROGEN_HANDLE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Keep this handle when cloning the namespace. Not allowed on namespace handles. */
#define HYDROGEN_HANDLE_CLONE_KEEP (1u << 0)

#define HYDROGEN_NAMESPACE_CLONE (1u << 0)   /**< Allow this namespace to be cloned. */
#define HYDROGEN_NAMESPACE_ADD (1u << 1)     /**< Allow handles to be added to this namespace. */
#define HYDROGEN_NAMESPACE_REMOVE (1u << 2)  /**< Allow handles to be removed from this namespace. */
#define HYDROGEN_NAMESPACE_RESOLVE (1u << 3) /**< Allow handles to be resolved from this namespace. */

/**
 * Pseudo-handle that refers to the current namespace.
 * Only valid as select function parameters, and may have a different meaning in others.
 *
 * This handle has the following rights (note that this list may expand in the future):
 * - #HYDROGEN_NAMESPACE_CLONE
 * - #HYDROGEN_NAMESPACE_ADD
 * - #HYDROGEN_NAMESPACE_REMOVE
 * - #HYDROGEN_NAMESPACE_RESOLVE
 */
#define HYDROGEN_THIS_NAMESPACE (-2)

#define HYDROGEN_INVALID_HANDLE (-1) /**< The handle equivalent of `NULL`. */

/**
 * Create an empty namespace.
 *
 * \param[in] flags The flags that should be set on the returned handle.
 * \return A handle to the newly created namespace, if successful; if not, a negative error code.
 */
int hydrogen_namespace_create(uint32_t flags) __asm__("__hydrogen_namespace_create");

/**
 * Create a new namespace by cloning an existing one.
 *
 * \param[in] ns The namespace to clone. Can be #HYDROGEN_THIS_NAMESPACE. Requires #HYDROGEN_NAMESPACE_CLONE.
 * \param[in] flags The flags that should be set on the returned handle.
 * \return A handle to the newly created namespace, if successful; if not, a negative error code.
 */
int hydrogen_namespace_clone(int ns, uint32_t flags) __asm__("__hydrogen_namespace_clone");

/**
 * Add a handle to a namespace.
 *
 * Note that namespace handles cannot be transferred to another namespace; if this is attempted, this function returns
 * #EPERM.
 *
 * \param[in] src_ns The namespace that `src_obj` should be resolved from. Can be #HYDROGEN_THIS_NAMESPACE.
 *                   Requires #HYDROGEN_NAMESPACE_RESOLVE.
 * \param[in] src_obj The object that the new handle should point to.
 * \param[in] dst_ns The namespace that the new handle should be created in. Can be #HYDROGEN_THIS_NAMESPACE.
 *                   Requires #HYDROGEN_NAMESPACE_ADD and, if `dst_obj` already points to an object,
 *                   #HYDROGEN_NAMESPACE_REMOVE.
 * \param[in] dst_hnd The new handle. If this handle already points to an object, the handle is removed first.
 *                    If this is #HYDROGEN_INVALID_HANDLE, a handle is allocated like normal.
 * \param[in] rights The rights that the new handle should have. This is masked with the rights of `src_obj`, so this
 *                   function can only remove rights, not add them.
 * \param[in] flags The flags that should be set on the returned handle.
 * \return The new handle, if successful; if not, a negative error code.
 */
int hydrogen_namespace_add(int src_ns, int src_obj, int dst_ns, int dst_hnd, uint32_t rights, uint32_t flags) __asm__(
        "__hydrogen_namespace_add"
);

/**
 * Remove a handle from a namespace.
 *
 * \param[in] ns The namespace that the handle should be removed from. Requires #HYDROGEN_NAMESPACE_REMOVE.
 * \param[in] handle The handle that should be removed.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_namespace_remove(int ns, int handle) __asm__("__hydrogen_namespace_remove");

/**
 * Resolve a handle.
 *
 * \param[in] ns The namespace that the handle should be resolved in. Can be #HYDROGEN_THIS_NAMESPACE.
 *               Requires #HYDROGEN_NAMESPACE_RESOLVE.
 * \param[in] handle The handle that should be resolved.
 * \param[out] rights The rights of the specified handle. Can be `NULL`.
 * \param[out] flags The flags of the specified handle. Can be `NULL`.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_namespace_resolve(int ns, int handle, uint32_t *rights, uint32_t *flags) __asm__("__hydrogen_namespace_resolve");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_HANDLE_H */
