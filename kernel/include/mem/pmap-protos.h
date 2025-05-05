/* IWYU pragma: private, include "arch/pmap.h" */
#pragma once

#include "arch/pmap-types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PMAP_READABLE (1 << 0)
#define PMAP_WRITABLE (1 << 1)
#define PMAP_EXECUTABLE (1 << 2)
#define PMAP_CACHE_MASK (3 << 3)
#define PMAP_CACHE_WB (0 << 3)
#define PMAP_CACHE_WT (1 << 3)
#define PMAP_CACHE_WC (2 << 3)
#define PMAP_CACHE_UC (3 << 3)
#define PMAP_USER (1 << 5)      /* internal */
#define PMAP_ANONYMOUS (1 << 5) /* internal */

/* definitions that need to be provided by arch code:
 * #define ARCH_PT_MAX_LEVEL ...
 *  the highest value arch_pt_levels() can return
 * #define ARCH_PT_PREPARE_PTE ...
 *  the pte that prepared-but-not-yet-mapped entries get filled with in debug mode.
 *  must not be recognized by the cpu as a valid entry.
 **/

/* return the highest allowed asid. must be constant and >= 0. */
static inline int arch_pt_max_asid(void);

/* switch to the target table and ensure there are no stale tlb entries.
 * if `asid` is negative, the table only contains kernel mappings.
 * if `current` is true, there were no other page tables using this asid switched
 * to between now and the last time this page table was switched to on this core.
 * always called with preemption disabled. */
static inline void arch_pt_switch(void *target, int asid, bool current);

/* the same as arch_switch_pt, except do any extra processing that is required for the first switch */
static inline void arch_pt_switch_init(void *target, int asid, bool current);

/* return the number of page table levels. must be constant. */
static inline unsigned arch_pt_levels(void);

/* return true if pages can be mapped directly in the given level */
static inline bool arch_pt_can_map_direct(unsigned level);

/* return the number of virtual address bits that vary within a single entry for the given level */
static inline unsigned arch_pt_entry_bits(unsigned level);

/* return the page table index for a given virtual address and page table level */
static inline size_t arch_pt_get_index(uintptr_t virt, unsigned level);

/* return the offset into a single mapping. if value is a multiple of PAGE_SIZE, this must return 0. */
static inline uint64_t arch_pt_get_offset(uint64_t value);

/* reads an entry from the given page table */
static inline pte_t arch_pt_read(void *table, unsigned level, size_t index);

/* writes an entry to the given page table */
static inline void arch_pt_write(void *table, unsigned level, size_t index, pte_t value);

/* create a pte that points to another page table */
static inline pte_t arch_pt_create_edge(unsigned level, void *target);

/* create a pte that maps a page */
static inline pte_t arch_pt_create_leaf(unsigned level, uint64_t target, int flags);

/* return true if the given pte points to another page table */
static inline bool arch_pt_is_edge(unsigned level, pte_t pte);

/* get the page table the given pte points to */
static inline void *arch_pt_edge_target(unsigned level, pte_t pte);

/* get the physical address the given pte points to */
static inline uint64_t arch_pt_leaf_target(unsigned level, pte_t pte);

/* returns the PMAP_* flags for the given leaf pte */
static inline int arch_pt_get_leaf_flags(unsigned level, pte_t pte);

/* return true if the given address is canonical */
static inline bool arch_pt_is_canonical(uintptr_t virt);

/* return true if replacing an empty pte with a leaf requires a flush. must be constant. */
static inline bool arch_pt_new_leaf_needs_flush(void);

/* return true if replacing an empty pte with an edge requires a flush. must be constant. */
static inline bool arch_pt_new_edge_needs_flush(void);

/* return true if arch_pt_flush_* honors the broadcast parameter. must be constant. */
static inline bool arch_pt_flush_can_broadcast(void);

/* return true if arch_pt_flush_edge flushes all edge pte(s) for the given asid. must be constant. */
static inline bool arch_pt_flush_edge_coarse(void);

/* flush any cached leaf pte(s) for the given address and asid. if `broadcast` is true,
 * and `arch_pt_flush_can_broadcast` returns true, do the same on all processors.
 * `table` is the last table that was switched to on the current processor with the given asid.
 * if `asid` is negative, this is a kernel mapping.
 * if `broadcast` is false, the mapping is in the page table that was last switched to
 * on this processor with the given asid.
 * if `current` is true, the mapping to be flushed comes from `table`.
 * always called with migration disabled. */
static inline void arch_pt_flush_leaf(uintptr_t virt, void *table, int asid, bool broadcast, bool current);

/* the same as arch_pt_flush_leaf, except flushes edge pte(s) instead of leaf pte(s) */
static inline void arch_pt_flush_edge(uintptr_t virt, void *table, int asid, bool broadcast, bool current);

/* flush all cached pte(s) on the current processor with the given asid.
 * `table` is the last table that was switched to on the current processor with the given asid.
 * if `asid` is negative, flush all cached kernel pte(s).
 * always called with migration disabled. */
static inline void arch_pt_flush(void *table, int asid);

/* wait for tlb flushes broadcasted by the current processor to complete */
static inline void arch_pt_flush_wait(void);

/* return the highest valid userspace address */
static inline uintptr_t arch_pt_max_user_addr(void);

/* return the highest valid index for the given level */
static inline size_t arch_pt_max_index(unsigned level);

/* initialize a new table for the given level. return false on failure. */
static inline bool arch_pt_init_table(void *table, unsigned level);

/* changes the permission flags for `pte` into `new_flags`.
 * returns true if a global flush is necessary. */
static inline bool arch_pt_change_permissions(pte_t *pte, unsigned level, int new_flags);
