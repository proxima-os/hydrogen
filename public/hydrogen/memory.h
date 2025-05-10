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

#define HYDROGEN_MEM_OBJECT_READ (1u << 0)  /**< Allow this object to explicitly be mapped for reading. */
#define HYDROGEN_MEM_OBJECT_WRITE (1u << 1) /**< Allow this object to be mapped for shared writing. */
#define HYDROGEN_MEM_OBJECT_EXEC (1u << 2)  /**< Allow this object to explicitly be mapped for execution. */

#define HYDROGEN_VMM_CLONE (1u << 0) /**< Allow this VMM to be cloned. */
#define HYDROGEN_VMM_MAP (1u << 1)   /**< Allow new mappings to be made in this VMM. */
#define HYDROGEN_VMM_REMAP (1u << 2) /**< Allow the permissions of mappings in this VMM to be changed. */
#define HYDROGEN_VMM_UNMAP (1u << 3) /**< Allow mappings to be removed from this VMM. */
#define HYDROGEN_VMM_READ (1u << 4)  /**< Allow data to be read from this VMM. */
#define HYDROGEN_VMM_WRITE (1u << 5) /**< Allow data to be written to this VMM. */

/**
 * Pseudo-handle that refers to the current VMM.
 * Only valid as select function parameters, and may have a different meaning in others.
 *
 * This handle has the following rights (note that this list may expand in the future):
 * - #HYDROGEN_VMM_CLONE
 * - #HYDROGEN_VMM_MAP
 * - #HYDROGEN_VMM_REMAP
 * - #HYDROGEN_VMM_UNMAP
 * - #HYDROGEN_VMM_READ
 * - #HYDROGEN_VMM_WRITE
 */
#define HYDROGEN_THIS_VMM (-2)

/**
 * Allow memory to be read from this region.
 *
 * Might be implied if #HYDROGEN_MEM_WRITE or #HYDROGEN_MEM_EXEC is specified.
 */
#define HYDROGEN_MEM_READ (1u << 0)

/**
 * Allow memory to be written to this region.
 */
#define HYDROGEN_MEM_WRITE (1u << 1)

/**
 * Allow instructions to be executed from this region.
 *
 * Might be implied if #HYDROGEN_MEM_READ or #HYDROGEN_MEM_WRITE is specified.
 */
#define HYDROGEN_MEM_EXEC (1u << 2)

/**
 * Fail if the region cannot be placed at the specified address.
 */
#define HYDROGEN_MEM_EXACT (1u << 3)

/**
 * Remove overlapping memory regions.
 *
 * Must be accompanied by #HYDROGEN_MEM_EXACT.
 */
#define HYDROGEN_MEM_OVERWRITE (1u << 4)

/**
 * Only reserve pages once they are accessed for the first time.
 */
#define HYDROGEN_MEM_LAZY_RESERVE (1u << 5)

/**
 * Propagate writes to the backing object and don't make it copy-on-write when cloned.
 *
 * Illegal on anonymous mappings.
 */
#define HYDROGEN_MEM_SHARED (1u << 6)

/**
 * The system's page size.
 */
extern const size_t hydrogen_page_size __asm__("__hydrogen_page_size");

/**
 * Create a new VMM.
 *
 * \param[in] flags The flags that should be set on the returned handle.
 * \return A handle to the newly created VMM, if successful; if not, a negative error code.
 */
int hydrogen_vmm_create(uint32_t flags) __asm__("__hydrogen_vmm_create");

/**
 * Create a new VMM by cloning an existing one.
 * Mappings without #HYDROGEN_MEM_SHARED will use copy-on-write.
 *
 * \param[in] vmm The VMM to clone. Can be #HYDROGEN_THIS_VMM. Requires #HYDROGEN_VMM_CLONE.
 * \param[in] flags The flags that should be set on the returned handle.
 * \return A handle to the newly created VMM, if successful; if not, a negative error code.
 */
int hydrogen_vmm_clone(int vmm, uint32_t flags) __asm__("__hydrogen_vmm_clone");

/**
 * Create a new memory mapping.
 *
 * If #HYDROGEN_MEM_EXACT is specified without #HYDROGEN_MEM_OVERWRITE, and `[hint,hint+size)` overlaps an existing
 * mapping in `vmm`, this function returns #EEXIST.
 *
 * \param[in] vmm The VMM to create the mapping in. Can be #HYDROGEN_THIS_VMM. Requires #HYDROGEN_VMM_MAP.
 * \param[in] hint The address the mapping should be created at. This is not a hard requirement unless
 *                 #HYDROGEN_MEM_EXACT is specified. Must be a multiple of the page size.
 * \param[in] size The size of the mapping. Must be a multiple of the page size.
 * \param[in] flags The flags the mapping should have.
 * \param[in] object The object to map. If this is #HYDROGEN_INVALID_HANDLE, an anonymous mapping is created.
 * \param[in] offset The offset within the object the mapping should start at. Must be a multiple of the page size.
 * \return The address of the mapping (in `pointer`), if successful; if not, an error code (in `error`).
 */
hydrogen_ret_t hydrogen_vmm_map(
        int vmm,
        uintptr_t hint,
        size_t size,
        uint32_t flags,
        int object,
        uint64_t offset
) __asm__("__hydrogen_vmm_map");

/**
 * Change the permissions of a range of memory.
 *
 * \param[in] vmm The VMM the range is in. Can be #HYDROGEN_THIS_VMM. Requires #HYDROGEN_VMM_REMAP.
 * \param[in] address The start of the range. Must be a multiple of the page size.
 * \param[in] size The size of the range. Must be a multiple of the page size.
 * \param[in] flags The new permissions of the range. Must not include any flags other than #HYDROGEN_MEM_READ,
 *                  #HYDROGEN_MEM_WRITE, and #HYDROGEN_MEM_EXEC.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_vmm_remap(int vmm, uintptr_t address, size_t size, uint32_t flags) __asm__("__hydrogen_vmm_remap");

/**
 * Move a range of memory.
 *
 * If `dst_addr` is not zero and `[dst_addr,dst_addr+dst_size)` overlaps an existing mapping in `dst_vmm`, this function
 * returns #EEXIST.
 *
 * \param[in] src_vmm The VMM the range is currently in. Can be #HYDROGEN_THIS_VMM. Requires #HYDROGEN_VMM_UNMAP and
 *                    #HYDROGEN_VMM_READ.
 * \param[in] src_addr The starting address of the range. Must be a multiple of the page size.
 * \param[in] src_size The size of the range. Must be a multiple of the page size.
 * \param[in] dst_vmm The VMM the range should be moved to. Can be #HYDROGEN_THIS_VMM. Requires #HYDROGEN_VMM_MAP.
 * \param[in] dst_addr The address the range should be moved to. Must be a multiple of the page size. If this is zero,
 *                     the kernel picks an address.
 * \param[in] dst_size The new size of the range. Must be a multiple of the page size, and must be greater than or equal
 *                     to `src_size`. If greater than `src_size`, the extra space is filled with a private anonymous
 *                     mapping with no permissions set.
 * \return The address of the mapping (in `pointer`), if successful; if not, an error code (in `error`).
 */
hydrogen_ret_t hydrogen_vmm_move(
        int src_vmm,
        uintptr_t src_addr,
        size_t src_size,
        int dst_vmm,
        uintptr_t dst_addr,
        size_t dst_size
) __asm__("__hydrogen_vmm_move");

/**
 * Unmap a range of memory.
 *
 * \param[in] vmm The VMM the range is in. Can be #HYDROGEN_THIS_VMM. Requires #HYDROGEN_VMM_UNMAP.
 * \param[in] address The starting address of the range. Must be a multiple of the page size.
 * \param[in] size The size of the range. Must be a multiple of the page size.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_vmm_unmap(int vmm, uintptr_t address, size_t size) __asm__("__hydrogen_vmm_unmap");

/**
 * Read data from a VMM.
 *
 * \param[in] vmm The VMM to read from. Can be #HYDROGEN_THIS_VMM. Requires #HYDROGEN_VMM_READ.
 * \param[in] buffer The buffer to write the data into.
 * \param[in] address The address to start reading from.
 * \param[in] size The number of bytes to read.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_vmm_read(int vmm, void *buffer, uintptr_t address, size_t size) __asm__("__hydrogen_vmm_read");

/**
 * Write data to a VMM.
 *
 * \param[in] vmm The VMM to write to. Can be #HYDROGEN_THIS_VMM. Requires #HYDROGEN_VMM_WRITE.
 * \param[in] buffer The buffer to read the data from.
 * \param[in] address The address to start writing to.
 * \param[in] size The number of bytes to write.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_vmm_write(int vmm, const void *buffer, uintptr_t address, size_t size) __asm__("__hydrogen_vmm_write");

/**
 * Wait on a memory location.
 *
 * This function atomically verifies that `location` still holds `expected` and, if so, goes to sleep. If the value
 * does not match, the function immediately returns #EAGAIN.
 *
 * \param[in] location The location to wait on. Must be aligned to a 4-byte boundary.
 * \param[in] expected The value expected to be at `location`.
 * \param[in] deadline The boot time value after which this operation will return #ETIMEDOUT. If zero, wait forever.
 * \result 0, if woken up by #hydrogen_memory_wake; if not, an error code.
 */
int hydrogen_memory_wait(uint32_t *location, uint32_t expected, uint64_t deadline) __asm__("__hydrogen_memory_wait");

/**
 * Wake threads sleeping in #hydrogen_memory_wait.
 *
 * \param[in] location The location whose waiters should be woken up. Must be aligned to a 4-byte boundary.
 * \param[in] count The maximum number of threads to wake up. If zero, all threads are awoken.
 * \return The number of threads that have been awoken (in `integer`), if successful; if not,
 *         an error code (in `error`).
 */
hydrogen_ret_t hydrogen_memory_wake(uint32_t *location, size_t count) __asm__("__hydrogen_memory_wake");

/**
 * Create a memory object.
 *
 * \param[in] size The size of the object. Must be a multiple of the page size.
 * \param[in] flags The flags that should be set on the returned handle.
 * \return A handle to the created memory object, if successful; if not, a negative error code.
 */
int hydrogen_mem_object_create(size_t size, uint32_t flags) __asm__("__hydrogen_mem_object_create");

/**
 * Read data from a memory object.
 *
 * \param[in] object The object to read from. Requires #HYDROGEN_MEM_OBJECT_READ.
 * \param[in] buffer The buffer to read the data in to.
 * \param[in] count The number of bytes to read.
 * \param[in] position The position to start reading at.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_mem_object_read(int object, void *buffer, size_t count, uint64_t position) __asm__(
        "__hydrogen_mem_object_read"
);

/**
 * Write data to a memory object.
 *
 * \param[in] object The object to write to. Requires #HYDROGEN_MEM_OBJECT_WRITE.
 * \param[in] buffer The buffer to write the data from.
 * \param[in] count The number of bytes to write.
 * \param[in] position The position to start writing at.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_mem_object_write(int object, const void *buffer, size_t count, uint64_t position) __asm__(
        "__hydrogen_mem_object_write"
);

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_MEMORY_H */
