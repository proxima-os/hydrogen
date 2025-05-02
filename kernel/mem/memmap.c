#include "mem/memmap.h"
#include "arch/memmap.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "limine.h"
#include "mem/pmap-flags.h"
#include "mem/pmap.h"
#include "sections.h"
#include "string.h"
#include "util/panic.h"
#include <stddef.h>
#include <stdint.h>

uintptr_t hhdm_base;
uintptr_t page_array_base;

static uint64_t max_phys_addr;

static struct limine_memmap_response *loader_map;
static uint64_t early_alloc_max;
static uint64_t early_alloc_idx;

static uint64_t min_page_head;
static uint64_t max_page_tail;

static void bounds_func(uint64_t head, uint64_t tail, void *ctx) {
    if (head < min_page_head) min_page_head = head;
    if (head > max_page_tail) max_page_tail = tail;
}

static void align_and_invoke(uint64_t head, uint64_t tail, void (*func)(uint64_t, uint64_t, void *), void *ctx) {
    uint64_t aligned_head = (head + PAGE_MASK) & ~PAGE_MASK;
    if (aligned_head < head) return;

    uint64_t aligned_tail = tail | PAGE_MASK;
    if (aligned_tail < aligned_head) aligned_tail = UINT64_MAX;
    if (aligned_tail > max_phys_addr) aligned_tail = max_phys_addr;
    if (aligned_tail < aligned_head) return;

    func(aligned_head, aligned_tail, ctx);
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
                align_and_invoke(area_head, area_tail, func, ctx);
            } else {
                if (area_tail < tail) area_tail = tail;
                continue;
            }
        }

        area_head = head;
        area_tail = tail;
        in_area = true;
    }

    if (in_area) align_and_invoke(area_head, area_tail, func, ctx);
}

static void determine_memory_bounds(void) {
    min_page_head = UINT64_MAX;
    max_page_tail = 0;
    iter_ram_areas(bounds_func, NULL);
    if (min_page_head > max_page_tail) panic("no addressable memory");
}

#define MAX_EARLY_VM_AREAS 4
static struct {
    uintptr_t head;
    uintptr_t tail;
} early_vm_areas[MAX_EARLY_VM_AREAS];
static size_t num_early_vm_areas;

static void add_early_vm_area(uintptr_t head, uintptr_t tail) {
    uintptr_t aligned_head = (head + PAGE_MASK) & ~PAGE_MASK;
    if (aligned_head < head) return;

    uintptr_t aligned_tail = tail | PAGE_MASK;
    if (aligned_head > aligned_tail) return;

    size_t idx = num_early_vm_areas++;
    ASSERT(idx < MAX_EARLY_VM_AREAS);

    early_vm_areas[idx].head = aligned_head;
    early_vm_areas[idx].tail = aligned_tail;
}

static uintptr_t early_vm_alloc(uintptr_t size) {
    size = (size + PAGE_MASK) & ~PAGE_MASK;
    ENSURE(size > 0);

    uintptr_t limit = size - 1;

    for (size_t i = 0; i < num_early_vm_areas; i++) {
        uintptr_t cur_base = early_vm_areas[i].head;
        uintptr_t cur_limit = early_vm_areas[i].tail - cur_base;

        if (limit < cur_limit) {
            early_vm_areas[i].head += size;
        } else if (limit > cur_limit) {
            continue;
        } else {
            memmove(&early_vm_areas[i], &early_vm_areas[i + 1], (num_early_vm_areas - i - 1) * sizeof(*early_vm_areas));
            num_early_vm_areas -= 1;
        }

        return cur_base;
    }

    return 0;
}

static void create_hhdm_func(uint64_t head, uint64_t tail, void *ctx) {
    pmap_early_map(hhdm_base + head, head, (tail - head) + 1, PMAP_READABLE | PMAP_WRITABLE);
}

struct create_page_array_ctx {
    uintptr_t head;
    uintptr_t tail;
    bool in_area;
};

static void create_page_array_finalize(struct create_page_array_ctx *ctx) {
    if (ctx->in_area) {
        size_t size = ctx->tail - ctx->head + 1;
        pmap_early_alloc(ctx->head, size, PMAP_READABLE | PMAP_WRITABLE);
        memset((void *)ctx->head, 0, size);

        ctx->in_area = false;
    }
}

static void create_page_array_func(uint64_t head, uint64_t tail, void *ptr) {
    struct create_page_array_ctx *ctx = ptr;

    uintptr_t parr_head = page_array_base + ((head >> PAGE_SHIFT) * sizeof(page_t));
    uintptr_t parr_tail = page_array_base + ((tail >> PAGE_SHIFT) * sizeof(page_t));

    parr_head &= ~PAGE_MASK;
    parr_tail |= PAGE_MASK;

    if (ctx->in_area) {
        if (ctx->tail + 1 < parr_head) {
            create_page_array_finalize(ctx);
        } else {
            ctx->tail = parr_tail;
            return;
        }
    }

    ctx->head = parr_head;
    ctx->tail = parr_tail;
    ctx->in_area = true;
}

static void map_segment(
        struct limine_executable_address_response *addr,
        const void *start,
        const void *end,
        int flags
) {
    uint64_t phys = addr->physical_base + ((uintptr_t)start - addr->virtual_base);
    size_t size = end - start;
    pmap_early_map((uintptr_t)start, phys, size, flags);
}

void memmap_init(void) {
    extern const void _start, _erodata, _etext, _end;

    static LIMINE_REQ struct limine_hhdm_request hhdm_req = {.id = LIMINE_HHDM_REQUEST};
    static LIMINE_REQ struct limine_executable_address_request kaddr_req = {.id = LIMINE_EXECUTABLE_ADDRESS_REQUEST};
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

    pmap_init();
    map_segment(kaddr_req.response, &_start, &_erodata, PMAP_READABLE);
    map_segment(kaddr_req.response, &_erodata, &_etext, PMAP_READABLE | PMAP_EXECUTABLE);
    map_segment(kaddr_req.response, &_etext, &_end, PMAP_READABLE | PMAP_WRITABLE);
    iter_ram_areas(create_hhdm_func, NULL);
    pmap_init_switch();

    uintptr_t real_hhdm_tail = hhdm_base + max_page_tail;

    if (real_hhdm_base < (uintptr_t)&_start) {
        add_early_vm_area(-kernel_virt_size, real_hhdm_base - 1);
        add_early_vm_area(real_hhdm_tail + 1, (uintptr_t)&_start - 1);
        add_early_vm_area((uintptr_t)&_end, UINTPTR_MAX);
    } else {
        add_early_vm_area(-kernel_virt_size, (uintptr_t)&_start - 1);
        add_early_vm_area((uintptr_t)&_end, real_hhdm_base - 1);
        add_early_vm_area(real_hhdm_tail + 1, UINTPTR_MAX);
    }

    size_t num_pages = ((max_page_tail - min_page_head) >> PAGE_SHIFT) + 1;
    size_t page_array_size = num_pages * sizeof(page_t);
    ENSURE((page_array_base = early_vm_alloc(page_array_size)) != 0);
    page_array_base -= (min_page_head >> PAGE_SHIFT) * sizeof(page_t);

    struct create_page_array_ctx ctx = {};
    iter_ram_areas(create_page_array_func, &ctx);
    create_page_array_finalize(&ctx);
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

        early_alloc_max = head ? head - 1 : 0;
        if (early_alloc_max <= entry->base) early_alloc_idx -= 1;

        return phys_to_virt(head);
    }

    panic("early_alloc_page out of memory");
}
