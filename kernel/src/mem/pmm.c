#include "mem/pmm.h"
#include "cpu/cpu.h"
#include "hydrogen/error.h"
#include "kernel/compiler.h"
#include "limine.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "sections.h"
#include "util/panic.h"
#include "util/spinlock.h"
#include <stdint.h>

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
    }
}

static void map_segment(const void *start, const void *end, int flags) {
    uint64_t phys = ((uintptr_t)start - addr_req.response->virtual_base) + addr_req.response->physical_base;
    hydrogen_error_t error = map_kernel_memory((uintptr_t)start, phys, end - start, flags, CACHE_WRITEBACK);
    if (unlikely(error)) panic("failed to map kernel segment (%d)", error);
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
    init_pmap();

    // create hhdm
    uint64_t map_start = 0;
    uint64_t map_end = 0;

    for (uint64_t i = 0; i < mmap_req.response->entry_count; i++) {
        struct limine_memmap_entry *entry = mmap_req.response->entries[i];
        if (entry->type != LIMINE_MEMMAP_USABLE && entry->type != LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE) continue;

        uint64_t start = entry->base;
        if (start >= pmm_addr_max) break;

        uint64_t end = start + entry->length;
        if (end == virt_to_phys(page_array)) end += page_array_size;
        if (end > pmm_addr_max) end = pmm_addr_max;
        if (start >= end) continue;

        if (map_end < start) {
            if (map_start != map_end) {
                hydrogen_error_t error = map_kernel_memory(
                        (uintptr_t)phys_to_virt(map_start),
                        map_start,
                        map_end - map_start,
                        PMAP_WRITE,
                        CACHE_WRITEBACK
                );
                if (unlikely(error)) panic("failed to create hhdm (%d)", error);
            }

            map_start = start;
        }

        map_end = end;
    }

    if (map_start != map_end) {
        hydrogen_error_t error = map_kernel_memory(
                (uintptr_t)phys_to_virt(map_start),
                map_start,
                map_end - map_start,
                PMAP_WRITE,
                CACHE_WRITEBACK
        );
        if (unlikely(error)) panic("failed to create hhdm (%d)", error);
    }

    // map kernel image
    map_segment(&_start, &_erodata, 0);
    map_segment(&_erodata, &_etext, PMAP_EXEC);
    map_segment(&_etext, &_end, PMAP_WRITE);

    pmap_init_switch();

    if (hhdm_start < &_start) {
        kvmm_add_range(min_kernel_address, (uintptr_t)hhdm_start - min_kernel_address);
        kvmm_add_range((uintptr_t)hhdm_start + pmm_addr_max, &_start - hhdm_start - pmm_addr_max);
        kvmm_add_range((uintptr_t)&_end, UINTPTR_MAX - (uintptr_t)&_end + 1);
    } else {
        kvmm_add_range(min_kernel_address, (uintptr_t)&_start);
        kvmm_add_range((uintptr_t)&_end, hhdm_start - &_end);
        kvmm_add_range((uintptr_t)hhdm_start + pmm_addr_max, UINTPTR_MAX - (uintptr_t)hhdm_start - pmm_addr_max + 1);
    }
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
    bool success = count <= pmm_stats.available;
    if (likely(success)) pmm_stats.available -= count;
    return success;
}

bool pmm_reserve(size_t count) {
    spin_lock_noirq(&pmm_lock);
    bool success = do_reserve(count);
    spin_unlock_noirq(&pmm_lock);
    return success;
}

void pmm_unreserve(size_t count) {
    spin_lock_noirq(&pmm_lock);
    pmm_stats.available += count;
    spin_unlock_noirq(&pmm_lock);
}

static inline page_t *do_alloc(void) {
    page_t *page = free_pages;
    size_t idx = --page->free.count;
    if (likely(idx == 0)) free_pages = page->free.next;
    pmm_stats.free -= 1;
    return page + idx;
}

page_t *pmm_alloc(void) {
    spin_lock_noirq(&pmm_lock);
    page_t *page = do_alloc();
    spin_unlock_noirq(&pmm_lock);
    return page;
}

static void do_free(page_t *page) {
    page->free.next = free_pages;
    free_pages = page;
    pmm_stats.free += 1;
}

void pmm_free(page_t *page) {
    page->free.count = 1;
    spin_lock_noirq(&pmm_lock);
    do_free(page);
    spin_unlock_noirq(&pmm_lock);
}

page_t *pmm_alloc_now(void) {
    spin_lock_noirq(&pmm_lock);

    if (unlikely(!do_reserve(1))) {
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
