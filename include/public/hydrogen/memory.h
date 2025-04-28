/** \file
 * Definitions for memory management.
 */

#ifndef HYDROGEN_MEMORY_H
#define HYDROGEN_MEMORY_H

#include "hydrogen/types.h"
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

#define HYDROGEN_MEM_READ (1u << 0)
#define HYDROGEN_MEM_WRITE (1u << 1)
#define HYDROGEN_MEM_EXEC (1u << 2)
#define HYDROGEN_MEM_SHARED (1u << 3)
#define HYDROGEN_MEM_NO_CACHE (1u << 4)
#define HYDROGEN_MEM_WRITE_COMBINE (2u << 4)
#define HYDROGEN_MEM_WRITE_THROUGH (3u << 4)
#define HYDROGEN_MEM_EXACT (1u << 6)
#define HYDROGEN_MEM_OVERWRITE (1u << 7)

#define HYDROGEN_MEMORY_RIGHT_READ (1ull << 0)    /**< Allow this object to be explicitly mapped for reading. */
#define HYDROGEN_MEMORY_RIGHT_WRITE (1ull << 1)   /**< Allow this object to be mapped for shared writing. */
#define HYDROGEN_MEMORY_RIGHT_EXEC (1ull << 2)    /**< Allow this object to be explicitly mapped for execution. */
#define HYDROGEN_MEMORY_RIGHT_CACHE (1ull << 3)   /**< Allow this object to be mapped with a non-default cache mode. */
#define HYDROGEN_MEMORY_RIGHT_PRIVATE (1ull << 4) /**< Allow private mappings to be backed by this object. */

#define HYDROGEN_VM_RIGHT_MAP (1ull << 0)   /**< Allow new mappings to be created in this address space. */
#define HYDROGEN_VM_RIGHT_REMAP (1ull << 1) /**< Allow mapping permissions to be changed in this address space. */
#define HYDROGEN_VM_RIGHT_UNMAP (1ull << 2) /**< Allow mappings to be removed in this address space. */
#define HYDROGEN_VM_RIGHT_CLONE (1ull << 3) /**< Allow a new address space to be created by cloning this one. */
#define HYDROGEN_VM_RIGHT_WRITE (1ull << 4) /**< Allow data to be written to this address space. */
#define HYDROGEN_VM_RIGHT_READ (1ull << 5)  /**< Allow data to be read from this address space. */

/**
 * The system page size.
 */
extern const size_t hydrogen_page_size __asm__("__hydrogen_page_size");

/**
 * Create a new address space.
 *
 * \return The newly created address space.
 */
hydrogen_ret_t hydrogen_vm_create(void) __asm__("__hydrogen_vm_create");

/**
 * Creates a new address space by cloning an existing one.
 * All anonymous mappings and non-shared object mappings are cloned using copy-on-write.
 *
 * \param[in] src The address space to clone. If `NULL`, use the current address space.
 * \return The newly created address space.
 */
hydrogen_ret_t hydrogen_vm_clone(hydrogen_handle_t src) __asm__("__hydrogen_vm_clone");

/**
 * Create a new memory mapping.
 *
 * If the mapping cannot be placed at the input address and #HYDROGEN_MEM_EXACT is not given, the kernel chooses
 * a suitable address. To force this behavior, pass `0` as the input address, as the first page is never allowed
 * to be mapped.
 *
 * \param[in] vm The address space to create the mapping in. If `NULL`, use the current address space.
 * \param[in] addr The address the mapping should be placed at. Must be page-aligned.
 * \param[in] size The size of the mapping. Must be page-aligned and non-zero.
 * \param[in] flags The mapping flags.
 * \param[in] object The object to map. If `NULL`, create an anonymous mapping.
 * \param[in] offset The offset into the object to map. Must be page-aligned, even if `object` is `NULL`.
 * \return The address the mapping was placed at.
 */
hydrogen_ret_t hydrogen_vm_map(
        hydrogen_handle_t vm,
        uintptr_t addr,
        size_t size,
        unsigned flags,
        hydrogen_handle_t object,
        size_t offset
) __asm__("__hydrogen_vm_map");

/**
 * Map the vDSO.
 *
 * This call fails if the vDSO has already been mapped in the given address space, or if the address space has ever
 * been used to create a thread.
 *
 * \param[in] vm The address space to map the vDSO in. If `NULL`, use the current address space.
 * \return The base address of the vDSO image.
 */
hydrogen_ret_t hydrogen_vm_map_vdso(hydrogen_handle_t vm) __asm__("__hydrogen_vm_map_vdso");

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
int hydrogen_vm_remap(hydrogen_handle_t vm, uintptr_t addr, size_t size, unsigned flags) __asm__("__hydrogen_vm_remap");

/**
 * Remove existing mappings.
 * All mappings between `addr` and `addr + size` are removed. Mappings that are partially outside this region are split.
 *
 * \param[in] vm The address space the mappings are in. If `NULL`, use the current address space.
 * \param[in] addr The starting address of the region to unmap.
 * \param[in] size The size of the region to unmap.
 */
int hydrogen_vm_unmap(hydrogen_handle_t vm, uintptr_t addr, size_t size) __asm__("__hydrogen_vm_unmap");

/**
 * Write memory to a remote address space.
 * Some error conditions can cause partial writes.
 *
 * \param[in] vm The address space to write to. Must not be the current address space.
 * \param[in] dest The virtual address in the target address space to write to.
 * \param[in] src The data to write.
 * \param[in] size The number of bytes to write. Must not be zero.
 */
int hydrogen_vm_write(hydrogen_handle_t vm, uintptr_t dest, const void *src, size_t size) __asm__("__hydrogen_vm_write"
);

/**
 * Fill memory in a remote address space.
 * Some error conditions can cause partial writes.
 *
 * \param[in] vm The address space to write to. Must not be the current address space.
 * \param[in] dest The virtual address in the target address space to write to.
 * \param[in] value The value to write to each byte.
 * \param[in] size The number of bytes to write. Must not be zero.
 */
int hydrogen_vm_fill(hydrogen_handle_t vm, uintptr_t dest, uint8_t value, size_t size) __asm__("__hydrogen_vm_fill");

/**
 * Read memory from a remote address space.
 * Some error conditions can cause partial reads.
 *
 * \param[in] vm The address space to read from. Must not be the current address space.
 * \param[in] dest The buffer to read the data into.
 * \param[in] src The virtual address in the target address space to read from.
 * \param[in] size The number of bytes to read. Must not be zero.
 */
int hydrogen_vm_read(hydrogen_handle_t vm, void *dest, uintptr_t src, size_t size) __asm__("__hydrogen_vm_read");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_MEMORY_H */
