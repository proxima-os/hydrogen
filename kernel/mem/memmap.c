#include "mem/memmap.h"
#include "arch/memmap.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "limine.h"
#include "sections.h"
#include "util/panic.h"
#include <stddef.h>
#include <stdint.h>

uintptr_t hhdm_base;

static uint64_t max_phys_addr;

static struct limine_memmap_response *loader_map;
static uint64_t early_alloc_max;
static uint64_t early_alloc_idx;

static uint64_t min_page_head;
static uint64_t max_page_tail;

static void bounds_func(uint64_t head, uint64_t tail, void *ctx) {
    uint64_t aligned_head = (head + PAGE_MASK) & ~PAGE_MASK;
    if (aligned_head < head) return;

    uint64_t aligned_tail = tail | PAGE_MASK;
    if (aligned_tail < aligned_head) aligned_tail = UINT64_MAX;
    if (aligned_tail > max_phys_addr) aligned_tail = max_phys_addr;
    if (aligned_tail < aligned_head) return;

    if (aligned_head < min_page_head) min_page_head = aligned_head;
    if (aligned_tail > max_page_tail) max_page_tail = aligned_tail;
}

static void iter_ram_areas(void (*func)(uint64_t, uint64_t, void *), void *ctx) {
    uint64_t area_head = 0;
    uint64_t area_tail = 0;
    bool in_area = false;

    for (uint64_t i = 0; i < loader_map->entry_count; i++) {
        struct limine_memmap_entry *entry = loader_map->entries[i];

        if (entry->type != LIMINE_MEMMAP_USABLE && entry->type != LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE &&
            entry->type != LIMINE_MEMMAP_EXECUTABLE_AND_MODULES) {
            continue;
        }

        if (entry->length == 0) {
            continue;
        }

        uint64_t head = entry->base;
        uint64_t tail = head + (entry->length - 1);
        if (tail < head) tail = UINT64_MAX;
        if (tail > max_phys_addr) tail = max_phys_addr;

        if (in_area) {
            if (area_tail + 1 < head) {
                func(area_head, area_tail, ctx);
            } else {
                if (area_tail < tail) area_tail = tail;
                continue;
            }
        }

        area_head = head;
        area_tail = tail;
        in_area = true;
    }

    if (in_area) func(area_head, area_tail, ctx);
}

static void determine_memory_bounds(void) {
    min_page_head = UINT64_MAX;
    max_page_tail = 0;
    iter_ram_areas(bounds_func, NULL);
    if (min_page_head > max_page_tail) panic("no addressable memory");
}

void memmap_init(void) {
    extern const void _start, _end;

    static LIMINE_REQ struct limine_hhdm_request hhdm_req = {.id = LIMINE_HHDM_REQUEST};
    static LIMINE_REQ struct limine_memmap_request memmap_req = {.id = LIMINE_MEMMAP_REQUEST};

    ENSURE(hhdm_req.response != NULL);
    ENSURE(memmap_req.response != NULL);

    hhdm_base = hhdm_req.response->offset;
    loader_map = memmap_req.response;

    max_phys_addr = cpu_max_phys_addr();
    determine_memory_bounds();

    uintptr_t real_hhdm_base = hhdm_base + min_page_head;
    uint64_t hhdm_max;

    if (real_hhdm_base < (uintptr_t)&_start) {
        hhdm_max = (uintptr_t)&_start - real_hhdm_base - 1;
    } else {
        ENSURE(real_hhdm_base >= (uintptr_t)&_end);
        hhdm_max = UINTPTR_MAX - real_hhdm_base;
    }

    if (hhdm_max < max_phys_addr) max_phys_addr = hhdm_max;

    unsigned kernel_virt_bits = cpu_vaddr_bits() - 1;
    ASSERT(kernel_virt_bits < 64);
    uint64_t kernel_virt_size = 1ull << kernel_virt_bits;
    hhdm_max = (kernel_virt_size / 2) - 1; // limit hhdm area to half of the kernel virtual address space
    if (hhdm_max < max_phys_addr) max_phys_addr = hhdm_max;

    max_phys_addr = (max_phys_addr - PAGE_MASK) | PAGE_MASK;
    determine_memory_bounds();

    early_alloc_max = max_phys_addr;
    early_alloc_idx = loader_map->entry_count;
}

void *early_alloc_page(void) {
    for (; early_alloc_idx > 0; early_alloc_idx--) {
        struct limine_memmap_entry *entry = loader_map->entries[early_alloc_idx - 1];
        if (entry->type != LIMINE_MEMMAP_USABLE) continue;
        if (!entry->length) continue;

        uint64_t tail = entry->base + (entry->length - 1);
        if (tail < entry->base) tail = UINT64_MAX;
        if (tail > early_alloc_max) tail = early_alloc_max;
        if (tail < PAGE_MASK) continue;

        uint64_t head = (tail - PAGE_MASK) & ~PAGE_MASK;
        if (head < entry->base) continue;

        entry->length = head - entry->base;
        if (!entry->length) early_alloc_idx -= 1;

        early_alloc_max = head ? head - 1 : 0;
        return phys_to_virt(head);
    }

    panic("early_alloc_page out of memory");
}
