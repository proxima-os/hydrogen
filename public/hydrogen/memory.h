#ifndef HYDROGEN_MEMORY_H
#define HYDROGEN_MEMORY_H

#ifdef __cplusplus
extern "C" {
#endif

#define HYDROGEN_MEM_OBJECT_READ (1u << 0)  /**< Allow this object to explicitly be mapped for reading. */
#define HYDROGEN_MEM_OBJECT_WRITE (1u << 1) /**< Allow this object to be mapped for shared writing. */
#define HYDROGEN_MEM_OBJECT_EXEC (1u << 2)  /**< Allow this object to explicitly be mapped for execution. */

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

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_MEMORY_H */
