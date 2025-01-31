#include "mem/pmm.h"
#include "cpu/cpu.h"
#include "kernel/compiler.h"
#include "limine.h"
#include "sections.h"
#include "util/panic.h"
#include "util/spinlock.h"

static page_t *free_pages;
static pmm_stats_t pmm_stats;
static spinlock_t pmm_lock;

_Static_assert(PAGE_SHIFT == 12, "PMM doesn't work with non-4k pages");

void *hhdm_start;
page_t *page_array;
uint64_t pmm_addr_max;

static LIMINE_REQ struct limine_hhdm_request hhdm_req = {.id = LIMINE_HHDM_REQUEST};
static LIMINE_REQ struct limine_executable_address_request addr_req = {.id = LIMINE_EXECUTABLE_ADDRESS_REQUEST};
static LIMINE_REQ struct limine_memmap_request mmap_req = {.id = LIMINE_MEMMAP_REQUEST};

extern const void _start;
extern const void _erodata;
extern const void _etext;
extern const void _end;

static void free_by_type(uint64_t type) {
    for (uint64_t i = 0; i < mmap_req.response->entry_count; i++) {
        struct limine_memmap_entry *entry = mmap_req.response->entries[i];
        if (entry->type != type) continue;
        if (entry->base >= pmm_addr_max) continue;
        if (entry->length == 0) continue;

        uint64_t end = entry->base + entry->length;
        if (end > pmm_addr_max) end = pmm_addr_max;

        page_t *page = phys_to_page(entry->base);
        page->free.count = (end - entry->base) >> PAGE_SHIFT;
        page->free.next = free_pages;
        free_pages = page;

        pmm_stats.total += page->free.count;
        pmm_stats.available += page->free.count;
        pmm_stats.free += page->free.count;

        entry->length = 0;
    }
}

void init_pmm(void) {
    if (!hhdm_req.response) panic("no response to hhdm request");
    if (!addr_req.response) panic("no response to address request");
    if (!mmap_req.response) panic("no response to memory map request");

    hhdm_start = (void *)hhdm_req.response->offset;
    pmm_addr_max = cpu_features.paddr_mask + 1;

    uint64_t hhdm_max;
    if (hhdm_start < &_start) hhdm_max = &_start - hhdm_start;
    else hhdm_max = UINTPTR_MAX - (uintptr_t)hhdm_start + 1;
    if (hhdm_max < pmm_addr_max) pmm_addr_max = hhdm_max;

    for (uint64_t i = mmap_req.response->entry_count; i > 0; i--) {
        struct limine_memmap_entry *entry = mmap_req.response->entries[i - 1];
        if (entry->type != LIMINE_MEMMAP_USABLE && entry->type != LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE) continue;
        if (entry->base >= pmm_addr_max) continue;
        if (entry->length == 0) continue;

        uint64_t end = entry->base + entry->length;
        if (end < pmm_addr_max) pmm_addr_max = end;
        break;
    }

    ASSERT((pmm_addr_max & PAGE_MASK) == 0);

    size_t page_array_size = ((pmm_addr_max >> PAGE_SHIFT) * sizeof(page_t) + PAGE_MASK) & ~PAGE_MASK;

    for (uint64_t i = mmap_req.response->entry_count; i > 0; i--) {
        struct limine_memmap_entry *entry = mmap_req.response->entries[i - 1];
        if (entry->type != LIMINE_MEMMAP_USABLE && entry->type != LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE) continue;
        if (entry->base >= pmm_addr_max) continue;
        if (entry->length == 0) continue;

        uint64_t end = entry->base + entry->length;
        if (end > pmm_addr_max) end = pmm_addr_max;

        uint64_t avail = end - entry->base;

        if (avail >= page_array_size) {
            entry->length = avail - page_array_size;
            page_array = phys_to_virt(entry->base + entry->length);
            break;
        }
    }

    free_by_type(LIMINE_MEMMAP_USABLE);
}

void reclaim_loader_pages(void) {
    spin_lock_noirq(&pmm_lock);
    free_by_type(LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE);
    spin_unlock_noirq(&pmm_lock);
}

pmm_stats_t pmm_get_stats(void) {
    spin_lock_noirq(&pmm_lock);
    pmm_stats_t stats = pmm_stats;
    spin_unlock_noirq(&pmm_lock);
    return stats;
}

static inline bool do_reserve(size_t count) {
    bool success = count >= pmm_stats.available;
    if (likely(success)) pmm_stats.available -= count;
    return success;
}

PMM_RESERVE {
    spin_lock_noirq(&pmm_lock);
    bool success = do_reserve(count);
    spin_unlock_noirq(&pmm_lock);

#if HYDROGEN_DEBUG_PMM
    if (likely(success)) {
        *out = (pmm_reservation_t){.__internal_total = count, .__internal_free = count};
    }
#endif

    return success;
}

#if HYDROGEN_DEBUG_PMM
bool pmm_extend(pmm_reservation_t *reservation, size_t extra) {
    spin_lock_noirq(&pmm_lock);
    bool success = do_reserve(extra);
    spin_unlock_noirq(&pmm_lock);

    if (likely(success)) {
        spin_lock_noirq(&reservation->lock);
        reservation->__internal_total += extra;
        reservation->__internal_free += extra;
        spin_unlock_noirq(&reservation->lock);
    }

    return success;
}
#endif

PMM_UNRESERVE {
#if HYDROGEN_DEBUG_PMM
    spin_lock_noirq(&reservation->lock);
    ASSERT(count <= reservation->__internal_total);
    ASSERT(count <= reservation->__internal_free);
    reservation->__internal_total -= count;
    reservation->__internal_free -= count;
    spin_unlock_noirq(&reservation->lock);
#endif

    spin_lock_noirq(&pmm_lock);
    pmm_stats.available += count;
    spin_unlock_noirq(&pmm_lock);
}

static inline page_t *do_alloc(void) {
    page_t *page = free_pages;
    size_t idx = --page->free.count;
    if (likely(idx == 0)) free_pages = page->free.next;
    pmm_stats.free -= 1;
    return page;
}

PMM_ALLOC {
#if HYDROGEN_DEBUG_PMM
    spin_lock_noirq(&reservation->lock);
    ASSERT(reservation->__internal_free >= 1);
    reservation->__internal_free -= 1;
    spin_unlock_noirq(&reservation->lock);
#endif

    spin_lock_noirq(&pmm_lock);
    page_t *page = do_alloc();
    spin_unlock_noirq(&pmm_lock);

#if HYDROGEN_DEBUG_PMM
    page->reservation = reservation;
#endif
    return page;
}

static void do_free(page_t *page) {
    page->free.next = free_pages;
    free_pages = page;
    pmm_stats.free += 1;
}

PMM_FREE {
#if HYDROGEN_DEBUG_PMM
    ASSERT(page->reservation == reservation);
    page->reservation = NULL;
#endif

    page->free.count = 1;
    spin_lock_noirq(&pmm_lock);
    do_free(page);
    spin_unlock_noirq(&pmm_lock);

#if HYDROGEN_DEBUG_PMM
    spin_lock_noirq(&reservation->lock);
    ASSERT(reservation->__internal_free < reservation->__internal_total);
    reservation->__internal_free += 1;
    spin_unlock_noirq(&reservation->lock);
#endif
}

page_t *pmm_alloc_now(void) {
    spin_lock_noirq(&pmm_lock);

    if (!do_reserve(1)) {
        spin_unlock_noirq(&pmm_lock);
        return NULL;
    }

    page_t *page = do_alloc();
    spin_unlock_noirq(&pmm_lock);
    return page;
}

void pmm_free_now(page_t *page) {
    page->free.count = 1;

    spin_lock_noirq(&pmm_lock);
    do_free(page);
    pmm_stats.available += 1;
    spin_unlock_noirq(&pmm_lock);
}
