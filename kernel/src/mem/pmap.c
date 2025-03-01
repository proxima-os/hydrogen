#include "mem/pmap.h"
#include "asm/cr.h"
#include "asm/idle.h"
#include "asm/irq.h"
#include "asm/tlb.h"
#include "cpu/cpu.h"
#include "cpu/exc.h"
#include "cpu/idt.h"
#include "cpu/irqvecs.h"
#include "cpu/lapic.h"
#include "hydrogen/error.h"
#include "hydrogen/memory.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "limine.h"
#include "mem/kmalloc.h"
#include "mem/pmm.h"
#include "mem/vmm.h"
#include "sections.h"
#include "string.h"
#include "sys/usermem.h"
#include "thread/mutex.h"
#include "util/panic.h"
#include "util/spinlock.h"
#include <stdint.h>

#define PTE_PRESENT (1ul << 0)
#define PTE_WRITABLE (1ul << 1)
#define PTE_USER (1ul << 2)
#define PTE_ACCESSED (1ul << 5)
#define PTE_DIRTY (1ul << 6)
#define PTE_HUGE (1ul << 7)
#define PTE_GLOBAL (1ul << 8)
#define PTE_ANON (1ul << 9) /* The entry is part of an anonymous mapping. Enables reference counting. */
#define PTE_COW (1ul << 10) /* The entry is currently mapping the backing region for a copy-on-write region. */
#define PTE_ADDR_MASK 0xffffffffff000
#define PTE_NX (1ul << 63)

#define PAT_FLAG(idx) ((((idx) & 4) << 5) | (((idx) & 3) << 3))
#define PTE_WRITEBACK PAT_FLAG(0ul)
#define PTE_WRITE_THROUGH PAT_FLAG(1ul)
#define PTE_NO_CACHE PAT_FLAG(3ul)
#define PTE_WRITE_COMBINE PAT_FLAG(5ul)
#define PTE_CACHE_BITS PAT_FLAG(7ul)

#define TABLE_FLAGS (PTE_PRESENT | PTE_WRITABLE | PTE_ACCESSED)

#define PT_SIZE 0x1000

static uint64_t *kernel_pt;
static mutex_t kernel_pt_lock;

uintptr_t max_user_address;
uintptr_t min_kernel_address;

_Static_assert(PAGE_SHIFT == 12, "pmap cannot handle non-4k pages");

static enum {
    PT_4LEVEL,
    PT_5LEVEL,
} pt_style;
static unsigned pt_top_shift;

typedef struct {
    pmap_t *pmap;
    page_t *free_pending;
    bool local;
    bool global;
} tlb_ctx_t;

static pmap_t *shootdown_pmap;
static spinlock_t shootdown_lock;
static size_t shootdown_count;

static void handle_ipi_shootdown(UNUSED idt_frame_t *frame, UNUSED void *ctx) {
    if (!shootdown_pmap || current_cpu.pmap == shootdown_pmap) {
        if (!shootdown_pmap && cpu_features.global_pages) {
            // toggling cr4.pge flushes all caches, including global entries
            size_t cr4 = read_cr4();
            write_cr4(cr4 ^ CR4_PGE);
            write_cr4(cr4);
        } else {
            write_cr3(read_cr3());
        }
    }

    __atomic_fetch_add(&shootdown_count, 1, __ATOMIC_RELEASE);
}

static void shootdown_local(pmap_t *pmap) {
    irq_state_t state = spin_lock(&pmap->cpus_lock);

    if (pmap->ncpus > (current_cpu.pmap == pmap)) {
        spin_lock_noirq(&shootdown_lock);

        shootdown_count = 0;
        shootdown_pmap = pmap;
        size_t num_trig_cpus = 0;

        for (cpu_t *cpu = pmap->cpus; cpu != NULL; cpu = cpu->pmap_next) {
            if (cpu != current_cpu_ptr) {
                num_trig_cpus += 1;
                send_ipi(VEC_IPI_SHOOTDOWN, cpu);
            }
        }

        // this has to be unlocked before waiting for completion, because otherwise it could deadlock:
        // - CPU 1 disables IRQs
        // - CPU 2 runs shootdown_local(A), which locks A->cpus_lock and sends VEC_IPI_SHOOTDOWN to CPU 1
        // - CPU 1 runs pmap_switch(B), which tries to lock A->cpus_lock
        // in this scenario CPU 2 won't release A->cpus_lock until CPU 1 has processed the shootdown, but CPU 1 won't
        // enable IRQs until it has acquired A->cpus_lock, so both CPUs deadlock. This is fixed by making CPU 2 unlock
        // A->cpus_lock before waiting for completion.
        spin_unlock_noirq(&pmap->cpus_lock);

        while (__atomic_load_n(&shootdown_count, __ATOMIC_ACQUIRE) != num_trig_cpus) cpu_relax();

        spin_unlock(&shootdown_lock, state);
    } else {
        spin_unlock(&pmap->cpus_lock, state);
    }
}

static void shootdown_global(void) {
    irq_state_t state = spin_lock(&shootdown_lock);

    shootdown_count = 0;
    shootdown_pmap = NULL;

    send_ipi(VEC_IPI_SHOOTDOWN, NULL);

    while (__atomic_load_n(&shootdown_count, __ATOMIC_ACQUIRE) != num_cpus - 1) cpu_relax();

    spin_unlock(&shootdown_lock, state);
}

static void tlb_init(tlb_ctx_t *ctx, pmap_t *pmap) {
    ctx->pmap = pmap;
    ctx->local = pmap == NULL || pmap == current_cpu.pmap;
}

static void tlb_add(tlb_ctx_t *ctx, uintptr_t addr) {
    if (likely(ctx->local)) {
        invlpg(addr);
    }
}

static void tlb_commit(tlb_ctx_t *ctx) {
    if (num_cpus > 1 && ctx->global) {
        if (ctx->pmap) shootdown_local(ctx->pmap);
        else shootdown_global();
    }

    for (page_t *page = ctx->free_pending; page != NULL; page = page->anon.tlb_next) {
        pmm_free(page);
    }
}

#define PF_ERROR_PRESENT 1
#define PF_ERROR_WRITE 2
#define PF_ERROR_USER 4
#define PF_ERROR_EXEC 16

static bool check_lazy_tlb(uintptr_t addr, uint64_t *table, uint64_t **ptr_out, uint64_t *ent_out, size_t error_code) {
    unsigned shift = pt_top_shift;
    uint64_t *ptr;
    uint64_t entry;

    do {
        ptr = &table[(addr >> shift) & 511];
        entry = __atomic_load_n(ptr, __ATOMIC_RELAXED);

        if (!entry) {
            if (ptr_out) *ptr_out = shift == 12 ? ptr : NULL;
            if (ent_out) *ent_out = 0;
            return false;
        }

        table = phys_to_virt(entry & PTE_ADDR_MASK);
        shift -= 9;
    } while (shift >= 12 && (entry & PTE_HUGE) == 0);

    if (ptr_out) *ptr_out = ptr;
    if (ent_out) *ent_out = entry;

    if ((error_code & PF_ERROR_WRITE) && unlikely(!(entry & PTE_WRITABLE))) return false;
    if ((error_code & PF_ERROR_EXEC) && unlikely(entry & PTE_NX)) return false;

    return true;
}

static bool is_usermem_func(uintptr_t pc) {
    return usermem_funcs.start <= pc && pc < usermem_funcs.end;
}

static void signal_user_fault(uintptr_t addr, idt_frame_t *frame, hydrogen_error_t error) {
    if (is_usermem_func(frame->rip)) {
        // See usermem.S
        frame->rax = error;
        frame->rip = usermem_funcs.ret;
        if (cpu_features.smap) frame->rflags &= ~(1ul << 18);
        return;
    }

    uintptr_t info[2] = {addr, frame->error_code};
    handle_user_exception(error, "page fault", frame, info);
}

static hydrogen_error_t get_obj_phys(uint64_t *out, vm_region_t *region, uintptr_t addr) {
    vm_object_t *object = (vm_object_t *)region->object.object;
    size_t offset = region->offset + ((addr & ~PAGE_MASK) - region->head);

    return ((const vm_object_ops_t *)object->base.ops)->get_phys(object, out, region, offset);
}

static uint64_t flags_to_pte(hydrogen_mem_flags_t flags) {
    uint64_t pte = 0;

    if (flags & HYDROGEN_MEM_WRITE) pte |= PTE_WRITABLE;
    if (cpu_features.nx && !(flags & HYDROGEN_MEM_EXEC)) pte |= PTE_NX;

    switch (flags & VM_CACHE_MODE_MASK) {
    default: pte |= PTE_WRITEBACK; break;
    case HYDROGEN_MEM_NO_CACHE: pte |= PTE_NO_CACHE; break;
    case HYDROGEN_MEM_WRITE_COMBINE: pte |= PTE_WRITE_COMBINE; break;
    case HYDROGEN_MEM_WRITE_THROUGH: pte |= PTE_WRITE_THROUGH; break;
    }

    return pte;
}

static uint64_t flags_to_map_pte(hydrogen_mem_flags_t flags) {
    return PTE_PRESENT | PTE_ACCESSED | PTE_DIRTY | flags_to_pte(flags);
}

static hydrogen_error_t try_create_mapping(vm_region_t *region, uintptr_t addr, uint64_t *ptr) {
    uint64_t entry = flags_to_map_pte(region->flags) | PTE_USER;

    if (region->object.object) {
        uint64_t phys;
        hydrogen_error_t error = get_obj_phys(&phys, region, addr);
        if (unlikely(error)) return error;

        if (!(region->flags & HYDROGEN_MEM_SHARED)) {
            // A possible performance optimization here is copying immediately if the fault was caused by a write.
            // This is harder to implement than it sounds, since `phys` might not be in the HHDM.
            // For now, just use the easy way out: write as read-only first, and fault again, at which point
            // the memory will be mapped and the existing mapping can be used as a copy source.
            entry &= ~PTE_WRITABLE;
            entry |= PTE_COW;
        }

        entry |= phys;
    } else {
        page_t *page = pmm_alloc();
        page->anon.references = 1;
        memset(page_to_virt(page), 0, PAGE_SIZE);
        entry |= page_to_phys(page);
        entry |= PTE_ANON;
    }

    __atomic_store_n(ptr, entry, __ATOMIC_RELAXED);
    return HYDROGEN_SUCCESS;
}

static bool deref_if_not_excl(page_t *page) {
    if (__atomic_fetch_sub(&page->anon.references, 1, __ATOMIC_ACQ_REL) == 1) {
        __atomic_store_n(&page->anon.references, 1, __ATOMIC_RELEASE);
        return false;
    }

    return true;
}

static bool is_user_fault(uintptr_t pc, uintptr_t addr, size_t error_code) {
    if (addr < PAGE_SIZE || addr >= max_user_address) return false;

    return (error_code & PF_ERROR_USER) || is_usermem_func(pc);
}

static bool is_access_allowed(vm_region_t *region, size_t error_code) {
    if (unlikely(!(region->flags & VM_PERM_MASK))) return false;
    if ((error_code & PF_ERROR_WRITE) && unlikely(!(region->flags & HYDROGEN_MEM_WRITE))) return false;
    if ((error_code & PF_ERROR_EXEC) && unlikely(!(region->flags & HYDROGEN_MEM_EXEC))) return false;
    return true;
}

static void do_cow_copy(address_space_t *space, uint64_t ent, uint64_t *ptr, uintptr_t addr) {
    ent &= ~PTE_COW;
    ent |= PTE_WRITABLE;

    // Perform copy
    if ((ent & PTE_ANON) == 0 || deref_if_not_excl(phys_to_page(ent & PTE_ADDR_MASK))) {
        page_t *dst = pmm_alloc();
        dst->anon.references = 1;

        // Using memcpy_user here because the target page might not be in HHDM.
        UNUSED hydrogen_error_t error = memcpy_user(page_to_virt(dst), (const void *)(addr & ~PAGE_MASK), PAGE_SIZE);
        ASSERT(!error); // The read-only mapping is currently present, so any page fault taken here is a bug.

        ent &= ~(PTE_ADDR_MASK | PTE_CACHE_BITS);
        ent |= page_to_phys(dst);
        ent |= PTE_ANON;
    }

    // We can't just insert the new entry immediately, since that causes a race condition with >=3 CPUs that allows
    // one CPU to read data from the old page after another CPU has already successfully written to the new page:
    // 1. CPU2 reads from the page, putting the read-only mapping into CPU2's TLB, and spins until a flag is set.
    // 2. CPU0 triggers the page fault. The page is copied and the new entry is inserted into the page table, but the
    //    shootdown hasn't been triggered yet.
    // 3. CPU1 writes to the page. It doesn't have the mapping in its TLB, so it fetches the new entry and writes to the
    //    page without causing a fault. It then sets the flag CPU2 is waiting on.
    // 4. CPU2 notices the flag is set, and reads the field CPU1 wrote. It still has the old read-only entry in its
    //    TLB, so it reads the old value in the read-only page, not the value CPU1 wrote.
    // 5. Only now does CPU0 trigger the shootdown, but it's too late.
    // This can be fixed by unmapping the page and shooting it down before inserting the new entry. If any other CPU
    // tries to access the page before the new entry is inserted, it will cause a page fault that tries to acquire
    // the address space lock. By the time it acquires the lock, the new entry will have been inserted, so the lazy
    // TLB code will treat it as a spurious page fault and userspace will retry the access.
    __atomic_store_n(ptr, 0, __ATOMIC_RELAXED);
    tlb_ctx_t ctx = {.pmap = &space->pmap, .global = true, .local = true};
    tlb_add(&ctx, addr);
    tlb_commit(&ctx);

    // Insert new mapping
    __atomic_store_n(ptr, ent, __ATOMIC_RELAXED);
}

static hydrogen_error_t handle_user_fault(
        address_space_t *space,
        uint64_t *ptr,
        uint64_t ent,
        uintptr_t addr,
        idt_frame_t *frame
) {
    vm_region_t *region = vm_get_region(space, addr);
    if (unlikely(!region)) return HYDROGEN_PAGE_FAULT;
    if (unlikely(!is_access_allowed(region, frame->error_code))) return HYDROGEN_PAGE_FAULT;

    // This cannot be moved to before vm_get_region because otherwise copy-on-write will be used for no-write regions.
    // PTE_COW also cannot be redefined to be illegal for no-write regions, otherwise vm_remap can be used to get
    // write access to the backing memory.
    if (ent) {
        if ((frame->error_code & PF_ERROR_WRITE) && (ent & PTE_COW)) {
            do_cow_copy(space, ent, ptr, addr);
            return HYDROGEN_SUCCESS;
        }

        // The only scenarios where PTE permissions don't match region permissions are tested for above. All others
        // are bugs.
        panic("mapped permissions don't match region permissions");
    }

    return try_create_mapping(region, addr, ptr);
}

static void handle_page_fault(idt_frame_t *frame, void *ctx) {
    uintptr_t addr = read_cr2();
    uint64_t *table = phys_to_virt(read_cr3());

    if (is_user_fault(frame->rip, addr, frame->error_code)) {
        enable_irq();

        address_space_t *space = current_thread->address_space;
        ASSERT(space != NULL);
        ASSERT(&space->pmap == current_cpu.pmap);
        mutex_lock(&space->lock);

        uint64_t *ptr;
        uint64_t ent;
        if (check_lazy_tlb(addr, table, &ptr, &ent, frame->error_code)) {
            mutex_unlock(&space->lock);
            invlpg(addr);
            return;
        }

        if (likely(ptr)) {
            hydrogen_error_t error = handle_user_fault(space, ptr, ent, addr, frame);
            mutex_unlock(&space->lock);
            if (unlikely(error)) signal_user_fault(addr, frame, error);
            return;
        }

        mutex_unlock(&space->lock);
        signal_user_fault(addr, frame, HYDROGEN_PAGE_FAULT);
        return;
    } else if (!(frame->error_code & PF_ERROR_USER)) {
        if (addr < min_kernel_address) handle_fatal_exception(frame, ctx);

        size_t top_idx = (addr >> pt_top_shift) & 511;
        mutex_lock(&kernel_pt_lock);

        // sync table with main kernel table if necessary
        uint64_t entry = __atomic_load_n(&kernel_pt[top_idx], __ATOMIC_RELAXED);
        if (entry != __atomic_load_n(&table[top_idx], __ATOMIC_RELAXED)) {
            __atomic_store_n(&table[top_idx], entry, __ATOMIC_RELAXED);
            mutex_unlock(&kernel_pt_lock);
            return;
        }

        if (check_lazy_tlb(addr, kernel_pt, NULL, NULL, frame->error_code)) {
            mutex_unlock(&kernel_pt_lock);
            invlpg(addr);
            return;
        }

        mutex_unlock(&kernel_pt_lock);
        handle_fatal_exception(frame, ctx);
    }

    signal_user_fault(addr, frame, HYDROGEN_PAGE_FAULT);
}

void init_pmap(void) {
    static LIMINE_REQ struct limine_paging_mode_request pmode_req = {
            .id = LIMINE_PAGING_MODE_REQUEST,
            .mode = LIMINE_PAGING_MODE_X86_64_5LVL,
            .min_mode = LIMINE_PAGING_MODE_X86_64_4LVL,
            .max_mode = LIMINE_PAGING_MODE_X86_64_5LVL,
    };

    kernel_pt = kmalloc(PT_SIZE);
    if (unlikely(!kernel_pt)) panic("failed to allocate kernel page table");
    memset(kernel_pt, 0, PT_SIZE);

    if (pmode_req.response) {
        switch (pmode_req.response->mode) {
        case LIMINE_PAGING_MODE_X86_64_4LVL: pt_style = PT_4LEVEL; break;
        case LIMINE_PAGING_MODE_X86_64_5LVL: pt_style = PT_5LEVEL; break;
        default: panic("invalid paging mode: %U", pmode_req.response->mode);
        }
    } else {
        pt_style = PT_4LEVEL;
    }

    switch (pt_style) {
    case PT_4LEVEL:
        max_user_address = 0x7ffffffff000;
        min_kernel_address = 0xffff800000000000;
        pt_top_shift = 39;
        break;
    case PT_5LEVEL:
        max_user_address = 0xfffffffffff000;
        min_kernel_address = 0xff00000000000000;
        pt_top_shift = 48;
        break;
    }

    idt_install(VEC_PAGE_FAULT, handle_page_fault, NULL);
    idt_install(VEC_IPI_SHOOTDOWN, handle_ipi_shootdown, NULL);
}

void pmap_init_switch(void) {
    if (cpu_features.global_pages) {
        size_t cr4 = read_cr4();
        write_cr4(cr4 & ~CR4_PGE);
        write_cr3(virt_to_phys(kernel_pt));
        write_cr4(cr4 | CR4_PGE);
    } else {
        write_cr3(virt_to_phys(kernel_pt));
    }
}

hydrogen_error_t pmap_create(pmap_t *out) {
    out->root = kmalloc(PT_SIZE);
    if (unlikely(!out->root)) return HYDROGEN_OUT_OF_MEMORY;
    memset(out->root, 0, PT_SIZE / 2);
    memcpy(&out->root[256], &kernel_pt[256], PT_SIZE / 2);
    return HYDROGEN_SUCCESS;
}

static void destroy_table(uint64_t *table, size_t max, int level) {
    for (size_t i = 0; i < max; i++) {
        uint64_t entry = table[i];
        if (!entry) continue;

        if (level != 0 && (entry & PTE_HUGE) == 0) {
            destroy_table(phys_to_virt(entry & PTE_ADDR_MASK), 512, level - 1);
        } else if (entry & PTE_ANON) {
            uint64_t phys = entry & PTE_ADDR_MASK;
            if (level != 0) phys &= ~0x1000;
            page_t *page = phys_to_page(phys);

            if (__atomic_fetch_sub(&page->anon.references, 1, __ATOMIC_ACQ_REL) == 1) {
                pmm_free(page);
            }
        }
    }

    pmm_free_now(virt_to_page(table));
}

void pmap_destroy(pmap_t *pmap) {
    switch (pt_style) {
    case PT_4LEVEL: destroy_table(pmap->root, 256, 3); break;
    case PT_5LEVEL: destroy_table(pmap->root, 256, 4); break;
    }
}

void pmap_switch(pmap_t *target) {
    pmap_t *old = current_cpu.pmap;
    if (old == target) return;

    if (old) {
        spin_lock_noirq(&old->cpus_lock);

        if (current_cpu.pmap_prev) current_cpu.pmap_prev->pmap_next = current_cpu.pmap_next;
        else old->cpus = current_cpu.pmap_next;

        if (current_cpu.pmap_next) current_cpu.pmap_next->pmap_prev = current_cpu.pmap_prev;

        old->ncpus -= 1;
        spin_unlock_noirq(&old->cpus_lock);
    }

    if (target) {
        write_cr3(virt_to_phys(target->root));

        spin_lock_noirq(&target->cpus_lock);

        current_cpu.pmap_prev = NULL;
        current_cpu.pmap_next = target->cpus;
        target->cpus = current_cpu_ptr;
        target->ncpus += 1;

        spin_unlock_noirq(&target->cpus_lock);
    } else {
        write_cr3(virt_to_phys(kernel_pt));
    }

    current_cpu.pmap = target;
}

static bool can_map_direct(unsigned level) {
    return level < 2 || (level == 2 && cpu_features.huge_1gb);
}

UNUSED static bool is_canonical(uintptr_t virt) {
    virt >>= (pt_top_shift + 8); // isolate the highest valid bit and everything above it
    return !virt || virt == UINTPTR_MAX >> (pt_top_shift + 8);
}

UNUSED static bool is_kernel_memory(uintptr_t virt) {
    ASSERT(is_canonical(virt));
    return virt & (1ul << 63);
}

static hydrogen_error_t do_prepare(pmap_t *pmap, uint64_t *table, int level, uintptr_t addr, size_t size) {
    if (level == 0) return HYDROGEN_SUCCESS;

    unsigned bits = level * 9 + 12;
    size_t index = (addr >> bits) & 511;
    size_t entry_size = 1ul << bits;
    size_t entry_mask = entry_size - 1;

    while (size > 0) {
        uint64_t entry = __atomic_load_n(&table[index], __ATOMIC_RELAXED);
        uint64_t *child;

        if (entry) {
            ASSERT((entry & PTE_HUGE) == 0);
            child = phys_to_virt(entry & PTE_ADDR_MASK);
        } else {
            child = kmalloc(PT_SIZE);
            if (unlikely(!child)) return HYDROGEN_OUT_OF_MEMORY;
            memset(child, 0, PT_SIZE);
            __atomic_store_n(&table[index], virt_to_phys(child) | TABLE_FLAGS | PTE_USER, __ATOMIC_RELAXED);
        }

        size_t cur = entry_size - (addr & entry_mask);
        if (cur > size) cur = size;

        hydrogen_error_t error = do_prepare(pmap, child, level - 1, addr, cur);
        if (unlikely(error)) return error;

        index += 1;
        addr += cur;
        size -= cur;
    }

    return HYDROGEN_SUCCESS;
}

hydrogen_error_t pmap_prepare(pmap_t *pmap, uintptr_t addr, size_t size) {
    ASSERT(((addr | size) & PAGE_MASK) == 0);
    ASSERT(size != 0);
    ASSERT(addr < addr + (size - 1));
    ASSERT((pmap == NULL) == is_kernel_memory(addr));
    ASSERT(is_kernel_memory(addr) == is_kernel_memory(addr + (size - 1)));

    if (!pmap) mutex_lock(&kernel_pt_lock);

    hydrogen_error_t error;
    switch (pt_style) {
    case PT_4LEVEL: error = do_prepare(pmap, pmap ? pmap->root : kernel_pt, 3, addr, size); break;
    case PT_5LEVEL: error = do_prepare(pmap, pmap ? pmap->root : kernel_pt, 4, addr, size); break;
    default: __builtin_unreachable();
    }

    if (!pmap) mutex_unlock(&kernel_pt_lock);
    return error;
}

static void do_map(uint64_t *table, int level, uintptr_t addr, size_t size, uint64_t pte) {
    unsigned bits = level * 9 + 12;
    size_t index = (addr >> bits) & 511;
    size_t entry_size = 1ul << bits;
    size_t entry_mask = entry_size - 1;

    while (size > 0) {
        if (level == 0) {
            ASSERT(__atomic_load_n(&table[index], __ATOMIC_RELAXED) == 0);
            __atomic_store_n(&table[index], pte, __ATOMIC_RELAXED);
            index += 1;
            addr += 0x1000;
            size -= 0x1000;
            pte += 0x1000;
            continue;
        }

        uint64_t entry = __atomic_load_n(&table[index], __ATOMIC_RELAXED);
        ASSERT(entry != 0);
        ASSERT((entry & PTE_HUGE) == 0);
        uint64_t *child = phys_to_virt(entry & PTE_ADDR_MASK);

        size_t cur = entry_size - (addr & entry_mask);
        if (cur > size) cur = size;

        do_map(child, level - 1, addr, cur, pte);

        index += 1;
        addr += cur;
        size -= cur;
        pte += cur;
    }
}

void pmap_map(pmap_t *pmap, uintptr_t addr, size_t size, uint64_t phys, hydrogen_mem_flags_t flags) {
    ASSERT(((addr | size) & PAGE_MASK) == 0);
    ASSERT(size != 0);
    ASSERT(addr < addr + (size - 1));
    ASSERT((pmap == NULL) == is_kernel_memory(addr));
    ASSERT(is_kernel_memory(addr) == is_kernel_memory(addr + (size - 1)));

    uint64_t pte = flags_to_map_pte(flags) | phys;
    if (!is_kernel_memory(addr)) pte |= PTE_USER;

    if (!pmap) mutex_lock(&kernel_pt_lock);

    switch (pt_style) {
    case PT_4LEVEL: do_map(pmap ? pmap->root : kernel_pt, 3, addr, size, pte); break;
    case PT_5LEVEL: do_map(pmap ? pmap->root : kernel_pt, 4, addr, size, pte); break;
    }

    if (!pmap) mutex_unlock(&kernel_pt_lock);
}

static void do_alloc(uint64_t *table, int level, uintptr_t addr, size_t size, uint64_t pte) {
    unsigned bits = level * 9 + 12;
    size_t index = (addr >> bits) & 511;
    size_t entry_size = 1ul << bits;
    size_t entry_mask = entry_size - 1;

    while (size > 0) {
        if (level == 0) {
            ASSERT(__atomic_load_n(&table[index], __ATOMIC_RELAXED) == 0);
            page_t *page = pmm_alloc();
            page->anon.references = 1;
            __atomic_store_n(&table[index], pte | page_to_phys(page), __ATOMIC_RELAXED);
            index += 1;
            addr += 0x1000;
            size -= 0x1000;
            continue;
        }

        uint64_t entry = __atomic_load_n(&table[index], __ATOMIC_RELAXED);
        ASSERT(entry != 0);
        ASSERT((entry & PTE_HUGE) == 0);
        uint64_t *child = phys_to_virt(entry & PTE_ADDR_MASK);

        size_t cur = entry_size - (addr & entry_mask);
        if (cur > size) cur = size;

        do_alloc(child, level - 1, addr, cur, pte);

        index += 1;
        addr += cur;
        size -= cur;
    }
}

void pmap_alloc(uintptr_t addr, size_t size, hydrogen_mem_flags_t flags) {
    ASSERT(((addr | size) & PAGE_MASK) == 0);
    ASSERT(size != 0);
    ASSERT(addr < addr + (size - 1));
    ASSERT(is_kernel_memory(addr));

    uint64_t pte = PTE_ANON | flags_to_map_pte(flags);

    mutex_lock(&kernel_pt_lock);

    switch (pt_style) {
    case PT_4LEVEL: do_alloc(kernel_pt, 3, addr, size, pte); break;
    case PT_5LEVEL: do_alloc(kernel_pt, 4, addr, size, pte); break;
    }

    mutex_unlock(&kernel_pt_lock);
}

static uint64_t get_new_entry(uint64_t old, uint64_t flags, int level) {
    if (level == 0) {
        old &= ~PTE_HUGE; // PAT bit in normal pages
    } else {
        old &= ~(1ul << 12); // PAT bit
        flags |= (flags & PTE_HUGE) << 5;
        flags &= ~PTE_HUGE;
    }

    if (old & PTE_COW) flags &= ~PTE_WRITABLE;

    old &= ~(PTE_WRITABLE | PTE_NX | (3ul << 3));
    return old | flags;
}

static bool need_shootdown(uint64_t old_entry, uint64_t new_entry, int level) {
    if ((old_entry & PTE_WRITABLE) && !(new_entry & PTE_WRITABLE)) return true;
    if (!(old_entry & PTE_NX) && (new_entry & PTE_NX)) return true;

    uint64_t pat_mask = (3u << 3) | (1u << (level ? 12 : 7));
    return (old_entry & pat_mask) != (new_entry & pat_mask);
}

static void do_clone(uint64_t *dst, uint64_t *src, int level, uintptr_t addr, size_t size, bool cow, tlb_ctx_t *tlb) {
    unsigned bits = level * 9 + 12;
    size_t index = (addr >> bits) & 511;
    size_t entry_size = 1ul << bits;
    size_t entry_mask = entry_size - 1;

    while (size > 0) {
        size_t cur = entry_size - (addr & entry_mask);
        if (cur > size) cur = size;

        uint64_t src_ent = __atomic_load_n(&src[index], __ATOMIC_RELAXED);

        if (src_ent != 0) {
            if (level == 0 || (src_ent & PTE_HUGE) != 0) {
                if (cow && (src_ent & PTE_WRITABLE) != 0) {
                    src_ent &= ~PTE_WRITABLE;
                    src_ent |= PTE_COW;
                    __atomic_store_n(&src[index], src_ent, __ATOMIC_RELAXED);
                    tlb_add(tlb, addr);
                    tlb->global = true;
                }

                if (src_ent & PTE_ANON) {
                    __atomic_fetch_add(&phys_to_page(src_ent & PTE_ADDR_MASK)->anon.references, 1, __ATOMIC_ACQ_REL);
                }

                __atomic_store_n(&dst[index], src_ent, __ATOMIC_RELAXED);
            } else {
                uint64_t dst_ent = __atomic_load_n(&dst[index], __ATOMIC_RELAXED);
                ASSERT(dst_ent != 0);
                ASSERT(!(dst_ent & PTE_HUGE));

                uint64_t *dst_child = phys_to_virt(dst_ent & PTE_ADDR_MASK);
                uint64_t *src_child = phys_to_virt(src_ent & PTE_ADDR_MASK);
                do_clone(dst_child, src_child, level - 1, addr, cur, cow, tlb);
            }
        }

        index += 1;
        addr += cur;
        size -= cur;
    }
}

void pmap_clone(pmap_t *pmap, pmap_t *src, uintptr_t addr, size_t size, bool cow) {
    ASSERT(pmap);
    ASSERT(src);
    ASSERT(((addr | size) & PAGE_MASK) == 0);
    ASSERT(size != 0);
    ASSERT(addr < addr + (size - 1));
    ASSERT(!is_kernel_memory(addr + (size - 1)));

    tlb_ctx_t tlb = {};
    tlb_init(&tlb, pmap);

    switch (pt_style) {
    case PT_4LEVEL: do_clone(pmap->root, src->root, 3, addr, size, cow, &tlb); break;
    case PT_5LEVEL: do_clone(pmap->root, src->root, 4, addr, size, cow, &tlb); break;
    }

    tlb_commit(&tlb);
}

static void do_remap(uint64_t *table, int level, uintptr_t addr, size_t size, uint64_t pte, tlb_ctx_t *tlb) {
    unsigned bits = level * 9 + 12;
    size_t index = (addr >> bits) & 511;
    size_t entry_size = 1ul << bits;
    size_t entry_mask = entry_size - 1;

    while (size > 0) {
        size_t cur = entry_size - (addr & entry_mask);
        if (cur > size) cur = size;

        uint64_t old_entry = __atomic_load_n(&table[index], __ATOMIC_RELAXED);

        if (old_entry != 0) {
            if (level == 0 || (old_entry & PTE_HUGE) != 0) {
                uint64_t new_entry = get_new_entry(old_entry, pte, level);

                if (old_entry != new_entry) {
                    __atomic_store_n(&table[index], new_entry, __ATOMIC_RELAXED);
                    tlb_add(tlb, addr);

                    if (need_shootdown(old_entry, new_entry, level)) {
                        tlb->global = true;
                    }
                }
            } else {
                uint64_t *child = phys_to_virt(old_entry & PTE_ADDR_MASK);
                do_remap(child, level - 1, addr, cur, pte, tlb);
            }
        }

        index += 1;
        addr += cur;
        size -= cur;
    }
}

void pmap_remap(pmap_t *pmap, uintptr_t addr, size_t size, hydrogen_mem_flags_t flags) {
    ASSERT(((addr | size) & PAGE_MASK) == 0);
    ASSERT(size != 0);
    ASSERT(addr < addr + (size - 1));
    ASSERT((pmap == NULL) == is_kernel_memory(addr));
    ASSERT(is_kernel_memory(addr) == is_kernel_memory(addr + (size - 1)));

    uint64_t pte = flags_to_pte(flags);

    tlb_ctx_t tlb = {};
    tlb_init(&tlb, pmap);
    if (!pmap) mutex_lock(&kernel_pt_lock);

    switch (pt_style) {
    case PT_4LEVEL: do_remap(pmap ? pmap->root : kernel_pt, 3, addr, size, pte, &tlb); break;
    case PT_5LEVEL: do_remap(pmap ? pmap->root : kernel_pt, 4, addr, size, pte, &tlb); break;
    }

    tlb_commit(&tlb);
    if (!pmap) mutex_unlock(&kernel_pt_lock);
}

static void do_unmap(uint64_t *table, int level, uintptr_t addr, size_t size, tlb_ctx_t *tlb) {
    unsigned bits = level * 9 + 12;
    size_t index = (addr >> bits) & 511;
    size_t entry_size = 1ul << bits;
    size_t entry_mask = entry_size - 1;

    while (size > 0) {
        size_t cur = entry_size - (addr & entry_mask);
        if (cur > size) cur = size;

        uint64_t old_entry = __atomic_load_n(&table[index], __ATOMIC_RELAXED);

        if (old_entry != 0) {
            if (level == 0 || (old_entry & PTE_HUGE) != 0) {
                __atomic_store_n(&table[index], 0, __ATOMIC_RELAXED);
                tlb_add(tlb, addr);
                tlb->global = true;

                if (old_entry & PTE_ANON) {
                    page_t *page = phys_to_virt(old_entry & PTE_ADDR_MASK);

                    if (__atomic_fetch_sub(&page->anon.references, 1, __ATOMIC_ACQ_REL) == 1) {
                        page->anon.tlb_next = tlb->free_pending;
                        tlb->free_pending = page;
                    }
                }
            } else {
                uint64_t *child = phys_to_virt(old_entry & PTE_ADDR_MASK);
                do_unmap(child, level - 1, addr, cur, tlb);
            }
        }

        index += 1;
        addr += cur;
        size -= cur;
    }
}

void pmap_unmap(pmap_t *pmap, uintptr_t addr, size_t size) {
    ASSERT(((addr | size) & PAGE_MASK) == 0);
    ASSERT(size != 0);
    ASSERT(addr < addr + (size - 1));
    ASSERT((pmap == NULL) == is_kernel_memory(addr));
    ASSERT(is_kernel_memory(addr) == is_kernel_memory(addr + (size - 1)));

    tlb_ctx_t tlb = {};
    tlb_init(&tlb, pmap);
    if (!pmap) mutex_lock(&kernel_pt_lock);

    switch (pt_style) {
    case PT_4LEVEL: do_unmap(pmap ? pmap->root : kernel_pt, 3, addr, size, &tlb); break;
    case PT_5LEVEL: do_unmap(pmap ? pmap->root : kernel_pt, 4, addr, size, &tlb); break;
    }

    tlb_commit(&tlb);
    if (!pmap) mutex_unlock(&kernel_pt_lock);
}

static void do_init_map(uint64_t *table, int level, uintptr_t addr, size_t size, uint64_t pte) {
    unsigned bits = level * 9 + 12;
    size_t index = (addr >> bits) & 511;
    size_t entry_size = 1ul << bits;
    size_t entry_mask = (entry_size - 1) & ~0xfff;

    while (size > 0) {
        size_t offset = addr & entry_mask;
        uint64_t entry = __atomic_load_n(&table[index], __ATOMIC_RELAXED);

        if (level == 0 || (can_map_direct(level) && offset == 0 && size >= entry_size && (pte & entry_mask) == 0)) {
            ASSERT(entry == 0);
            entry = pte;

            if (level != 0) {
                entry |= PTE_HUGE | ((pte & PTE_HUGE) << 5);
            }

            __atomic_store_n(&table[index], entry, __ATOMIC_RELAXED);

            index += 1;
            addr += entry_size;
            size -= entry_size;
            pte += entry_size;
            continue;
        }

        uint64_t *child;

        if (entry == 0) {
            child = kmalloc(PT_SIZE);
            if (unlikely(!child)) panic("do_init_map out of memory");
            memset(child, 0, PT_SIZE);
            __atomic_store_n(&table[index], virt_to_phys(child) | TABLE_FLAGS, __ATOMIC_RELAXED);
        } else {
            ASSERT((entry & PTE_HUGE) == 0);
            child = phys_to_virt(entry & PTE_ADDR_MASK);
        }

        size_t cur = entry_size - offset;
        if (cur > size) cur = size;

        do_init_map(child, level - 1, addr, cur, pte);

        index += 1;
        addr += cur;
        size -= cur;
        pte += cur;
    }
}

void pmap_init_map(uintptr_t addr, size_t size, uint64_t phys, hydrogen_mem_flags_t flags) {
    ASSERT(((addr | size | phys) & PAGE_MASK) == 0);
    ASSERT(size != 0);
    ASSERT(addr < addr + (size - 1));
    ASSERT(is_kernel_memory(addr));

    uint64_t pte = flags_to_map_pte(flags) | phys;

    mutex_lock(&kernel_pt_lock);

    switch (pt_style) {
    case PT_4LEVEL: do_init_map(kernel_pt, 3, addr, size, pte); break;
    case PT_5LEVEL: do_init_map(kernel_pt, 4, addr, size, pte); break;
    }

    mutex_unlock(&kernel_pt_lock);
}
