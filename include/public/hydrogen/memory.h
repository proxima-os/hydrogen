/** \file
 * Definitions for memory management.
 */

#ifndef HYDROGEN_MEMORY_H
#define HYDROGEN_MEMORY_H

#include "hydrogen/error.h"
#include "hydrogen/handle.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Flags used when mapping memory.
 *
 * Note: if any protection flag is given, #HYDROGEN_MEM_READ and/or #HYDROGEN_MEM_EXEC may be implied.
 */
typedef enum {
    HYDROGEN_MEM_READ = 1 << 0,          /**< Allow reading from this memory region. */
    HYDROGEN_MEM_WRITE = 1 << 1,         /**< Allow writing to this memory region. */
    HYDROGEN_MEM_EXEC = 1 << 2,          /**< Allow executing code in this memory region. */
    HYDROGEN_MEM_SHARED = 1 << 3,        /**< Propagate writes to the backing object. Illegal for anonymous mappings. */
    HYDROGEN_MEM_NO_CACHE = 1 << 4,      /**< Don't cache memory accesses. */
    HYDROGEN_MEM_WRITE_COMBINE = 2 << 4, /**< Use write-combining caching or stronger for this memory region. */
    HYDROGEN_MEM_WRITE_THROUGH = 3 << 4, /**< Use write-through caching or stronger for this memory region. */
    HYDROGEN_MEM_EXACT = 1 << 6,         /**< Fail if the mapping cannot be placed at the specified address. */
    HYDROGEN_MEM_OVERWRITE = 1 << 7,     /**< If combined with #HYDROGEN_MEM_EXACT, remove existing mappings. */
} hydrogen_mem_flags_t;

#define HYDROGEN_MEMORY_RIGHT_READ (1ull << 0)    /**< Allow this object to be explicitly mapped for reading. */
#define HYDROGEN_MEMORY_RIGHT_WRITE (1ull << 1)   /**< Allow this object to be mapped for shared writing. */
#define HYDROGEN_MEMORY_RIGHT_EXEC (1ull << 2)    /**< Allow this object to be explicitly mapped for execution. */
#define HYDROGEN_MEMORY_RIGHT_CACHE (1ull << 3)   /**< Allow this object to be mapped with a non-default cache mode. */
#define HYDROGEN_MEMORY_RIGHT_PRIVATE (1ull << 4) /**< Allow private mappings to be backed by this object. */

#define HYDROGEN_VM_RIGHT_MAP (1ull << 0)   /**< Allow new mappings to be created in this address space. */
#define HYDROGEN_VM_RIGHT_REMAP (1ull << 1) /**< Allow mapping permissions to be changed in this address space. */
#define HYDROGEN_VM_RIGHT_UNMAP (1ull << 2) /**< Allow mappings to be removed in this address space. */
#define HYDROGEN_VM_RIGHT_CLONE (1ull << 3) /**< Allow a new address space to be created by cloning this one. */

/**
 * The system page size.
 */
extern const size_t hydrogen_page_size;

/**
 * Create a new address space.
 *
 * \param[out] vm The newly created address space.
 */
hydrogen_error_t hydrogen_vm_create(hydrogen_handle_t *vm);

/**
 * Creates a new address space by cloning an existing one.
 * All anonymous mappings and non-shared object mappings are cloned using copy-on-write.
 *
 * \param[out] vm The newly created address space.
 * \param[in] src The address space to clone. If `NULL`, use the current address space.
 */
hydrogen_error_t hydrogen_vm_clone(hydrogen_handle_t *vm, hydrogen_handle_t src);

/**
 * Create a new memory mapping.
 *
 * If the mapping cannot be placed at the input address and #HYDROGEN_MEM_EXACT is not given, the kernel chooses
 * a suitable address. To force this behavior, pass `0` as the input address, as the first page is never allowed
 * to be mapped.
 *
 * \param[in] vm The address space to create the mapping in. If `NULL`, use the current address space.
 * \param[in,out] addr The address of the mapping. Must be page-aligned.
 * \param[in] size The size of the mapping. Must be page-aligned and non-zero.
 * \param[in] flags The mapping flags.
 * \param[in] object The object to map. If `NULL`, create an anonymous mapping.
 * \param[in] offset The offset into the object to map. Must be page-aligned, even if `object` is `NULL`.
 */
hydrogen_error_t hydrogen_vm_map(
        hydrogen_handle_t vm,
        uintptr_t *addr,
        size_t size,
        hydrogen_mem_flags_t flags,
        hydrogen_handle_t object,
        size_t offset
);

/**
 * Map the vDSO.
 *
 * This call fails if the vDSO has already been mapped in the given address space, or if the address space has ever
 * been used to create a thread.
 *
 * \param[in] vm The address space to map the vDSO in. If `NULL`, use the current address space.
 * \param[out] addr The base address of the vDSO image.
 */
hydrogen_error_t hydrogen_vm_map_vdso(hydrogen_handle_t vm, uintptr_t *addr);

/**
 * Change the permissions of existing mappings.
 * All mappings between `addr` and `addr + size` have their permissions changed to reflect `flags`. Mappings that are
 * partially outside this region are split.
 *
 * \param[in] vm The address space the mappings are in. If `NULL`, use the current address space.
 * \param[in] addr The starting address of the region to change.
 * \param[in] size The size of the region to change.
 * \param[in] flags The new permissions for the region. Must only specify protection flags.
 */
hydrogen_error_t hydrogen_vm_remap(hydrogen_handle_t vm, uintptr_t addr, size_t size, hydrogen_mem_flags_t flags);

/**
 * Remove existing mappings.
 * All mappings between `addr` and `addr + size` are removed. Mappings that are partially outside this region are split.
 *
 * \param[in] vm The address space the mappings are in. If `NULL`, use the current address space.
 * \param[in] addr The starting address of the region to unmap.
 * \param[in] size The size of the region to unmap.
 */
hydrogen_error_t hydrogen_vm_unmap(hydrogen_handle_t vm, uintptr_t addr, size_t size);

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_MEMORY_H */
