#ifndef HYDROGEN_MEMORY_H
#define HYDROGEN_MEMORY_H

/*
 * Omitting a protection flag does not guarantee that the corresponding access type is not allowed. Specifically,
 * if any protection flag is given, `HYDROGEN_MEM_READ` and/or `HYDROGEN_MEM_EXEC` may be implied.
 */

typedef enum {
    HYDROGEN_MEM_READ = 1 << 0,          /* Allow reading from this memory region. */
    HYDROGEN_MEM_WRITE = 1 << 1,         /* Allow writing to this memory region. */
    HYDROGEN_MEM_EXEC = 1 << 2,          /* Allow executing code in this memory region. */
    HYDROGEN_MEM_SHARED = 1 << 3,        /* Propagate writes to the backing object. Illegal for anonymous mappings. */
    HYDROGEN_MEM_NO_CACHE = 1 << 4,      /* Don't cache memory accesses. */
    HYDROGEN_MEM_WRITE_COMBINE = 2 << 4, /* Use write-combining caching or stronger for this memory region. */
    HYDROGEN_MEM_WRITE_THROUGH = 3 << 4, /* Use write-through caching or stronger for this memory region. */
    HYDROGEN_MEM_EXACT = 1 << 6,         /* Fail if the mapping cannot be placed at the specified address. */
    HYDROGEN_MEM_OVERWRITE = 1 << 7,     /* If combined with HYDROGEN_MEM_EXACT, remove existing mappings. */
} hydrogen_mem_flags_t;

#endif /* HYDROGEN_MEMORY_H */
