#ifndef HYDROGEN_MEMORY_H
#define HYDROGEN_MEMORY_H

#ifdef __cplusplus
extern "C" {
#endif

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
 * Remove overlapping memory regions. Must be accompanied by #HYDROGEN_MEM_EXACT.
 */
#define HYDROGEN_MEM_OVERWRITE (1u << 4)

/**
 * Only reserve pages once they are accessed for the first time.
 */
#define HYDROGEN_MEM_LAZY_RESERVE (1u << 5)

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_MEMORY_H */
