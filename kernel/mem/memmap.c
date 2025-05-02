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

static struct limine_memmap_response *loader_map;
static uint64_t early_alloc_max;
static uint64_t early_alloc_idx;

void memmap_init(void) {
    static LIMINE_REQ struct limine_hhdm_request hhdm_req = {.id = LIMINE_HHDM_REQUEST};
    static LIMINE_REQ struct limine_memmap_request memmap_req = {.id = LIMINE_MEMMAP_REQUEST};

    ENSURE(hhdm_req.response != NULL);
    ENSURE(memmap_req.response != NULL);

    hhdm_base = hhdm_req.response->offset;
    loader_map = memmap_req.response;
    early_alloc_max = cpu_max_phys_addr();
    early_alloc_idx = loader_map->entry_count;
}

void *early_alloc_page(void) {
    for (; early_alloc_idx > 0; early_alloc_idx--) {
        struct limine_memmap_entry *entry = loader_map->entries[early_alloc_idx - 1];
        if (entry->type != LIMINE_MEMMAP_USABLE) continue;
        if (!entry->length) continue;

        uint64_t tail = entry->base + (entry->length - 1);
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
