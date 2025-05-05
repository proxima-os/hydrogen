#include "mem/memmap.h"
#include "arch/memmap.h"
#include "arch/pmap.h"
#include "cpu/cpudata.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "limine.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/vmalloc.h"
#include "sections.h"
#include "string.h"
#include "util/panic.h"
#include "util/slist.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

uintptr_t hhdm_base;
uintptr_t page_array_base;
uint64_t kernel_base;

static uint64_t max_phys_addr;

static struct limine_memmap_response *loader_map;
static uint64_t early_alloc_max;
static uint64_t early_alloc_idx;

static uint64_t min_page_head;
static uint64_t max_page_tail;

typedef struct {
    slist_node_t node;
    uint64_t head;
    uint64_t tail;
    bool kernel_owned : 1;
} ram_range_t;

static slist_t ram_list;

static void bounds_func(uint64_t head, uint64_t tail, void *ctx) {
    if (head < min_page_head) min_page_head = head;
    if (head > max_page_tail) max_page_tail = tail;
}

static bool align_bounds(uint64_t *head, uint64_t *tail) {
    uint64_t aligned_head = (*head + PAGE_MASK) & ~PAGE_MASK;
    if (aligned_head < *head) return false;

    uint64_t aligned_tail = (*tail - PAGE_MASK) | PAGE_MASK;
    if (aligned_tail > *tail) return false;
    if (aligned_tail > max_phys_addr) aligned_tail = max_phys_addr;
    if (aligned_tail < aligned_head) return false;

    *head = aligned_head;
    *tail = aligned_tail;
    return true;
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
                if (align_bounds(&area_head, &area_tail)) {
                    func(area_head, area_tail, ctx);
                }
            } else {
                if (area_tail < tail) area_tail = tail;
                continue;
            }
        }

        area_head = head;
        area_tail = tail;
        in_area = true;
    }

    if (in_area && align_bounds(&area_head, &area_tail)) {
        func(area_head, area_tail, ctx);
    }
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

static void map_segment(const void *start, const void *end, int flags) {
    pmap_early_map((uintptr_t)start, sym_to_phys(start), (uintptr_t)end - (uintptr_t)start, flags);
}

static void commit_usable(uint64_t head, uint64_t tail) {
    if (head < early_alloc_max) {
        if (tail <= early_alloc_max) {
            pmem_add_area(head, tail, true);
            return;
        } else {
            pmem_add_area(head, early_alloc_max, true);
            head = early_alloc_max + 1;
        }
    }

    pmem_add_area(head, tail, false);
}

static void add_areas(bool free) {
    uint64_t wanted_type = free ? LIMINE_MEMMAP_USABLE : LIMINE_MEMMAP_EXECUTABLE_AND_MODULES;

    uint64_t area_head = 0;
    uint64_t area_tail = 0;
    bool in_area = false;

    for (uint64_t i = 0; i < loader_map->entry_count; i++) {
        struct limine_memmap_entry *entry = loader_map->entries[i];
        if (entry->type != wanted_type || entry->length == 0) continue;

        uint64_t head = entry->base;
        uint64_t tail = head + (entry->length - 1);
        if (tail < head) tail = UINT64_MAX;
        if (tail > max_page_tail) tail = max_page_tail;
        if (tail <= head) continue;

        if (in_area) {
            if (area_tail + 1 < head) {
                if (align_bounds(&area_head, &area_tail)) {
                    if (free) {
                        commit_usable(area_head, area_tail);
                    } else {
                        pmem_add_area(area_head, area_tail, false);
                    }
                }
            } else {
                area_tail = tail;
                continue;
            }
        }

        area_head = head;
        area_tail = tail;
        in_area = true;
    }

    if (in_area && align_bounds(&area_head, &area_tail)) {
        if (free) {
            commit_usable(area_head, area_tail);
        } else {
            pmem_add_area(area_head, area_tail, false);
        }
    }
}

struct add_hhdm_gaps_ctx {
    uint64_t next_head;
};

static void add_hhdm_gaps(uint64_t head, uint64_t tail, void *ptr) {
    struct add_hhdm_gaps_ctx *ctx = ptr;

    if (ctx->next_head < head) {
        uint64_t gap_tail = head - 1;
        ASSERT(gap_tail <= max_page_tail);
        kvmm_add_range(hhdm_base + ctx->next_head, hhdm_base + gap_tail);
    }

    ctx->next_head = tail + 1;
}

struct build_ram_list_ctx {
    uint64_t head;
    uint64_t tail;
    bool owned;
    bool in_area;
};

static void ram_list_add(uint64_t head, uint64_t tail, bool owned) {
    ram_range_t *range = vmalloc(sizeof(*range));
    if (unlikely(!range)) panic("memmap: out of memory while creating ram list");

    memset(range, 0, sizeof(*range));
    range->head = head;
    range->tail = tail;
    range->kernel_owned = owned;
    slist_insert_tail(&ram_list, &range->node);
}

static void ram_list_commit(struct build_ram_list_ctx *ctx) {
    if (!ctx->in_area) return;

    if (ctx->owned) {
        uint64_t aligned_head = (ctx->head + PAGE_MASK) & ~PAGE_MASK;
        uint64_t aligned_tail = (ctx->tail - PAGE_MASK) | PAGE_MASK;

        if (aligned_head < ctx->head || aligned_tail > ctx->tail || aligned_head > aligned_tail) {
            ram_list_add(ctx->head, ctx->tail, false);
        } else {
            if (ctx->head < aligned_head) {
                ram_list_add(ctx->head, aligned_head - 1, false);
            }

            ram_list_add(aligned_head, aligned_tail, true);

            if (aligned_tail < ctx->tail) {
                ram_list_add(aligned_tail + 1, ctx->tail, false);
            }
        }
    } else {
        ram_list_add(ctx->head, ctx->tail, ctx->owned);
    }

    ctx->in_area = false;
}

static void ram_list_append(struct build_ram_list_ctx *ctx, uint64_t head, uint64_t tail, bool owned) {
    if (owned) {
        if (head < min_page_head) {
            if (tail < min_page_head) {
                owned = false;
            } else {
                ram_list_append(ctx, head, min_page_head - 1, false);
                head = min_page_head;
            }
        } else if (tail > max_page_tail) {
            if (head <= max_page_tail) {
                ram_list_append(ctx, head, max_page_tail, true);
                head = max_page_tail + 1;
            }

            owned = false;
        }
    }

    if (ctx->in_area) {
        if (ctx->tail + 1 >= head && ctx->owned == owned) {
            if (ctx->tail < tail) ctx->tail = tail;
            return;
        }

        ram_list_commit(ctx);
    }

    ctx->head = head;
    ctx->tail = tail;
    ctx->owned = owned;
    ctx->in_area = true;
}

static void build_ram_list(void) {
    struct build_ram_list_ctx ctx = {};
    uint64_t max = cpu_max_phys_addr();

    for (uint64_t i = 0; i < loader_map->entry_count; i++) {
        struct limine_memmap_entry *entry = loader_map->entries[i];
        if (entry->length == 0) continue;

        bool cur_owned;

        if (entry->type == LIMINE_MEMMAP_USABLE || entry->type == LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE ||
            entry->type == LIMINE_MEMMAP_EXECUTABLE_AND_MODULES) {
            cur_owned = true;
        } else if (entry->type == LIMINE_MEMMAP_ACPI_RECLAIMABLE || entry->type == LIMINE_MEMMAP_ACPI_NVS) {
            cur_owned = false;
        } else {
            continue;
        }

        uint64_t cur_head = entry->base;
        uint64_t cur_tail = cur_head + (entry->length - 1);
        if (cur_tail < cur_head) cur_tail = UINT64_MAX;
        if (cur_tail > max) cur_tail = max;
        if (cur_head > cur_tail) continue;

        ram_list_append(&ctx, cur_head, cur_tail, cur_owned);
    }

    ram_list_commit(&ctx);
}

void memmap_init(void) {
    extern const void _start, _erodata, _etext, _end;

    static LIMINE_REQ struct limine_hhdm_request hhdm_req = {.id = LIMINE_HHDM_REQUEST};
    static LIMINE_REQ struct limine_executable_address_request kaddr_req = {.id = LIMINE_EXECUTABLE_ADDRESS_REQUEST};
    static LIMINE_REQ struct limine_memmap_request memmap_req = {.id = LIMINE_MEMMAP_REQUEST};

    ENSURE(hhdm_req.response != NULL);
    ENSURE(memmap_req.response != NULL);

    hhdm_base = hhdm_req.response->offset;
    kernel_base = kaddr_req.response->physical_base + ((uintptr_t)&_start - kaddr_req.response->virtual_base);
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

    early_alloc_max = max_page_tail;
    early_alloc_idx = loader_map->entry_count;

    pmap_init();
    map_segment(&_start, &_erodata, PMAP_READABLE);
    map_segment(&_erodata, &_etext, PMAP_READABLE | PMAP_EXECUTABLE);
    map_segment(&_etext, &_end, PMAP_READABLE | PMAP_WRITABLE);
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
    pmap_early_cleanup();

    early_alloc_idx = 0; // disable early allocator

    add_areas(false);
    add_areas(true);

    for (size_t i = 0; i < num_early_vm_areas; i++) {
        kvmm_add_range(early_vm_areas[i].head, early_vm_areas[i].tail);
    }

    num_early_vm_areas = 0;

    struct add_hhdm_gaps_ctx ctx2 = {.next_head = min_page_head};
    iter_ram_areas(add_hhdm_gaps, &ctx2);

    pmap_init_cpu(get_current_cpu());
    build_ram_list();
}

struct reclaim_ctx {
    uint64_t reclaim_head;
    uint64_t reclaim_tail;
    uint64_t usable_head;
    uint64_t usable_tail;
    bool in_reclaim;
    bool in_usable;
};

#define ADD_TO_TYPE(type, ctx, head, tail)           \
    ({                                               \
        uint64_t _head = (head);                     \
        uint64_t _tail = (tail);                     \
        struct reclaim_ctx *_ctx = &(ctx);           \
        do {                                         \
            if (_ctx->in_##type) {                   \
                if (_ctx->type##_tail + 1 < _head) { \
                    type##_commit(_ctx);             \
                } else {                             \
                    _ctx->type##_tail = _tail;       \
                    break;                           \
                }                                    \
            }                                        \
                                                     \
            _ctx->type##_head = _head;               \
            _ctx->type##_tail = _tail;               \
            _ctx->in_##type = true;                  \
        } while (0);                                 \
    })

static void reclaim_commit(struct reclaim_ctx *ctx) {
    if (ctx->in_reclaim && align_bounds(&ctx->reclaim_head, &ctx->reclaim_tail)) {
        pmem_add_area(ctx->reclaim_head, ctx->reclaim_tail, true);
    }
}

static void usable_commit(struct reclaim_ctx *ctx) {
    uint64_t ahead = ctx->usable_head, atail = ctx->usable_tail;
    if (ctx->in_usable && align_bounds(&ahead, &atail)) {
        if (ahead != ctx->usable_head) ADD_TO_TYPE(reclaim, *ctx, ctx->usable_head, ahead - 1);
        if (ctx->usable_tail != atail) ADD_TO_TYPE(reclaim, *ctx, atail + 1, ctx->usable_tail);
    }
}

void memmap_reclaim_loader(void) {
    ASSERT(loader_map != NULL);

    struct reclaim_ctx ctx = {};

    for (uint64_t i = 0; i < loader_map->entry_count; i++) {
        struct limine_memmap_entry *entry = loader_map->entries[i];
        if (entry->type != LIMINE_MEMMAP_USABLE && entry->type != LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE) continue;
        if (entry->length == 0) continue;

        uint64_t head = entry->base;
        uint64_t tail = head + (entry->length - 1);
        if (tail < head) tail = UINT64_MAX;
        if (tail > max_page_tail) tail = max_page_tail;
        if (tail <= head) continue;

        if (entry->type == LIMINE_MEMMAP_USABLE) {
            ADD_TO_TYPE(usable, ctx, head, tail);
            continue;
        }

        ADD_TO_TYPE(reclaim, ctx, head, tail);
    }

    usable_commit(&ctx);
    reclaim_commit(&ctx);

    loader_map = NULL;
}

#undef ADD_TO_TYPE

void *early_alloc_page(void) {
    ASSERT(loader_map != NULL);

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

bool next_owned_ram_gap(uint64_t addr, uint64_t *head, uint64_t *tail) {
    uint64_t gap_head = 0;
    uint64_t max = cpu_max_phys_addr();

    SLIST_FOREACH(ram_list, ram_range_t, node, range) {
        if (range->kernel_owned) {
            if (gap_head < range->head) {
                uint64_t gap_tail = range->head - 1;

                if (addr <= gap_tail) {
                    *head = gap_head;
                    *tail = gap_tail;
                    return true;
                }
            }

            if (range->tail == max) {
                return false;
            }

            gap_head = range->tail + 1;
        }
    }

    *head = gap_head;
    *tail = cpu_max_phys_addr();
    return true;
}

bool is_area_ram(uint64_t head, uint64_t tail) {
    SLIST_FOREACH(ram_list, ram_range_t, node, range) {
        if (range->tail < head) continue;
        if (head < range->head) return false;
        if (tail <= range->tail) return true;
        head = range->tail + 1;
    }

    return false;
}
