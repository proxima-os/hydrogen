#include "mem/pmap.h"
#include "arch/idle.h"
#include "arch/irq.h"
#include "arch/memmap.h"
#include "arch/pmap.h"
#include "cpu/cpudata.h"
#include "cpu/smp.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "kernel/types.h"
#include "mem/memmap.h"
#include "mem/pmem.h"
#include "mem/vmalloc.h"
#include "proc/mutex.h"
#include "proc/sched.h"
#include "string.h"
#include "util/hlist.h"
#include "util/panic.h"
#include "util/shlist.h"
#include "util/spinlock.h"
#include <stddef.h>
#include <stdint.h>

#ifndef NDEBUG
#define PT_PREPARE_DEBUG 1
#else
#define PT_PREPARE_DEBUG 0
#endif

static void *kernel_page_table;
static mutex_t kernel_pt_lock;
static bool kernel_pt_switched;

typedef struct {
    pmap_t *pmap;
    void *table;
    shlist_t free_queue;
    int asid;
    bool current : 1;
    bool broadcasted : 1;
    bool edge : 1;
    bool edge_global : 1;
    bool global : 1;
} tlb_ctx_t;

static void tlb_init(tlb_ctx_t *tlb, pmap_t *pmap) {
    memset(tlb, 0, sizeof(*tlb));
    tlb->pmap = pmap;
    tlb->table = pmap ? pmap->table : kernel_page_table;
    tlb->asid = pmap ? pmap->asid : -1;
    tlb->current = __atomic_load_n(&kernel_pt_switched, __ATOMIC_RELAXED);
}

static void tlb_add_leaf(tlb_ctx_t *tlb, uintptr_t addr, bool global) {
    arch_pt_flush_leaf(addr, tlb->table, tlb->asid, global, tlb->current);

    if (global) {
        if (!arch_pt_flush_can_broadcast()) {
            tlb->global = true;
        } else {
            tlb->broadcasted = true;
        }
    }
}

static void tlb_add_edge(tlb_ctx_t *tlb, uintptr_t addr, bool global) {
    if (!arch_pt_flush_edge_coarse()) {
        arch_pt_flush_edge(addr, tlb->table, tlb->asid, global, tlb->current);

        if (global) {
            if (!arch_pt_flush_can_broadcast()) {
                tlb->global = true;
            } else {
                tlb->broadcasted = true;
            }
        }
    } else {
        tlb->edge = true;
        if (global) tlb->edge_global = true;
    }
}

struct tlb_remote_ctx {
    tlb_ctx_t *tlb;
    size_t pending;
};

static void tlb_remote(void *ptr) {
    struct tlb_remote_ctx *ctx = ptr;

    if (ctx->tlb->pmap) {
        if (get_current_cpu()->pmap.asids[ctx->tlb->asid].table == ctx->tlb->table) {
            arch_pt_flush(ctx->tlb->table, ctx->tlb->asid);
        }

        __atomic_fetch_sub(&ctx->pending, 1, __ATOMIC_RELEASE);
    } else {
        arch_pt_flush(kernel_page_table, -1);
    }
}

static void tlb_commit(tlb_ctx_t *tlb) {
    if (tlb->edge) {
        arch_pt_flush_edge(0, tlb->table, tlb->asid, tlb->edge_global, tlb->current);

        if (tlb->edge_global) {
            if (!arch_pt_flush_can_broadcast()) {
                tlb->global = true;
            } else {
                tlb->broadcasted = true;
            }
        }
    }

    if (tlb->broadcasted) {
        arch_pt_flush_wait();
    } else if (tlb->global) {
        struct tlb_remote_ctx ctx = {tlb, 0};

        if (tlb->pmap != NULL && tlb->global) {
            cpu_t *cur = get_current_cpu();

            preempt_state_t state = preempt_lock();
            spin_acq_noirq(&tlb->pmap->cpus_lock);

            HLIST_FOREACH(tlb->pmap->cpus, pmap_asid_data_t, node, asid) {
                if (asid->cpu != cur) {
                    __atomic_fetch_add(&ctx.pending, 1, __ATOMIC_ACQUIRE);
                    smp_call_remote_async(asid->cpu, tlb_remote, &ctx);
                }
            }

            spin_rel_noirq(&tlb->pmap->cpus_lock);
            preempt_unlock(state);

            while (__atomic_load_n(&ctx.pending, __ATOMIC_ACQUIRE) != 0) {
                cpu_relax();
            }
        } else {
            smp_call_remote(NULL, tlb_remote, &ctx);
        }
    }

    for (;;) {
        page_t *page = SHLIST_REMOVE_HEAD(tlb->free_queue, page_t, anon.free_node);
        if (!page) break;
        pmem_free(page);
    }
}

static void *early_alloc_table(unsigned level) {
    void *table = early_alloc_page();
    memset(table, 0, PAGE_SIZE);
    return table;
}

void pmap_init(void) {
    kernel_page_table = early_alloc_table(arch_pt_levels() - 1);
}

void pmap_init_switch(void) {
    arch_pt_switch_init(kernel_page_table, -1, false);
    __atomic_store_n(&kernel_pt_switched, true, __ATOMIC_RELAXED);
}

void pmap_init_cpu(cpu_t *cpu) {
    size_t num = arch_pt_max_asid() + 1;
    size_t size = num * sizeof(*cpu->pmap.asids);
    cpu->pmap.asids = vmalloc(size);
    if (unlikely(!cpu->pmap.asids)) panic("pmap: failed to initialize cpu asid map");
    memset(cpu->pmap.asids, 0, size);

    for (size_t i = 0; i < num; i++) {
        cpu->pmap.asids[i].cpu = cpu;
    }
}

static void *alloc_table(unsigned level) {
    page_t *page = pmem_alloc_now();
    if (unlikely(!page)) return NULL;
    page->anon.references = 0;
    void *table = page_to_virt(page);
    bool ok = arch_pt_init_table(table, level);
    if (unlikely(!ok)) pmem_free_now(page);
    return ok ? table : NULL;
}

static void free_table(void *table) {
    pmem_free_now(virt_to_page(table));
}

static void free_tables(void *table, unsigned level, size_t min_idx, size_t max_idx);

static void free_entry(pte_t pte, unsigned level) {
#if PT_PREPARE_DEBUG
    if (pte == ARCH_PT_PREPARE_PTE) return;
#endif

    if (level == 0 || !arch_pt_is_edge(level, pte)) {
        int flags = arch_pt_get_leaf_flags(level, pte);

        if ((flags & PMAP_ANONYMOUS) != 0) {
            ASSERT(level == 0);

            page_t *page = phys_to_page(arch_pt_leaf_target(level, pte));

            if (__atomic_fetch_sub(&page->anon.references, 1, __ATOMIC_ACQ_REL) == 1) {
                pmem_free(page);
            }
        }
    } else {
        void *table = arch_pt_edge_target(level, pte);
        free_tables(table, level - 1, 0, arch_pt_max_index(level - 1));
        free_table(table);
    }
}

static void free_tables(void *table, unsigned level, size_t min_idx, size_t max_idx) {
    for (size_t index = min_idx; index <= max_idx; index++) {
        free_entry(arch_pt_read(table, level, index), level);
    }
}

int pmap_create(pmap_t *out) {
    static uint64_t next_asid;

    memset(out, 0, sizeof(*out));
    if (unlikely(!(out = alloc_table(arch_pt_levels() - 1)))) return ENOMEM;
    out->asid = __atomic_fetch_add(&next_asid, 1, __ATOMIC_RELAXED) % (arch_pt_max_asid() + 1);

    return 0;
}

void pmap_switch(pmap_t *target) {
    ASSERT(target != NULL);

    cpu_t *cpu = get_current_cpu();
    pmap_t *old = cpu->pmap.current;
    if (target == old) return;

    pmap_asid_data_t *asid = &cpu->pmap.asids[target->asid];

    // tlb_remote accesses this stuff from irq context
    irq_state_t state = save_disable_irq();

    if (old->asid == target->asid) {
        if ((uintptr_t)old < (uintptr_t)target) {
            spin_acq_noirq(&old->cpus_lock);
            spin_acq_noirq(&target->cpus_lock);
        } else {
            spin_acq_noirq(&target->cpus_lock);
            spin_acq_noirq(&old->cpus_lock);
        }

        hlist_remove(&old->cpus, &asid->node);

        // this has to be done while both old->cpus_lock and target->cpus_lock is held
        //  if old->cpus_lock isn't held, pmap_destroy(old) might free the tables before we're ready
        //  if target->cpus_lock isn't held, tlb_commit on target might not flush tlb entries for us
        arch_pt_switch(target->table, target->asid, target->table == asid->table);

        spin_rel_noirq(&old->cpus_lock);
    } else {
        spin_acq_noirq(&target->cpus_lock);
        arch_pt_switch(target->table, target->asid, target->table == asid->table);
    }

    asid->table = target->table;
    cpu->pmap.current = target;
    hlist_insert_head(&target->cpus, &asid->node);
    spin_rel_noirq(&target->cpus_lock);

    restore_irq(state);
}

static void switch_away(void *ctx) {
    cpu_t *cpu = ctx;
    ASSERT(ctx == get_current_cpu());

    arch_pt_switch(kernel_page_table, -1, true);
    cpu->pmap.current = NULL;
}

void pmap_destroy(pmap_t *pmap) {
    // ensure no cpus are using this pmap
    preempt_state_t state = preempt_lock();
    spin_acq_noirq(&pmap->cpus_lock);

    for (;;) {
        pmap_asid_data_t *asid = HLIST_HEAD(pmap->cpus, pmap_asid_data_t, node);
        ASSERT(asid->table == pmap->table);

        if (asid->cpu->pmap.current == pmap) {
            if (asid->cpu == get_current_cpu()) {
                switch_away(asid->cpu);
            } else {
                smp_call_remote(asid->cpu, switch_away, asid->cpu);
            }
        }

        asid->table = NULL;
        hlist_remove(&pmap->cpus, &asid->node);
    }

    spin_rel_noirq(&pmap->cpus_lock);
    preempt_unlock(state);

    unsigned level = arch_pt_levels() - 1;
    free_tables(pmap->table, level, 0, arch_pt_get_index(arch_pt_max_user_addr(), level));
    free_table(pmap->table);
}

static void tlb_add_unmap_anon(tlb_ctx_t *tlb, page_t *page) {
    if (__atomic_fetch_sub(&page->anon.references, 1, __ATOMIC_ACQ_REL) == 1) {
        shlist_insert_head(&tlb->free_queue, &page->anon.free_node);
    }
}

static void tlb_add_unmap_leaf(tlb_ctx_t *tlb, uintptr_t addr, unsigned level, pte_t pte) {
    tlb_add_leaf(tlb, addr, true);

    int flags = arch_pt_get_leaf_flags(level, pte);

    if (flags & PMAP_ANONYMOUS) {
        tlb_add_unmap_anon(tlb, phys_to_page(arch_pt_leaf_target(level, pte)));
    }
}

static size_t do_unmap(void *table, unsigned level, uintptr_t virt, size_t size, tlb_ctx_t *tlb) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    size_t leaves = 0;

    do {
        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        pte_t pte = arch_pt_read(table, level, index);

        if (level == 0) {
#if PT_PREPARE_DEBUG
            ASSERT(pte != 0);
#endif

            if (pte != 0) {
                arch_pt_write(table, level, index, 0);

                if (!PT_PREPARE_DEBUG || pte != ARCH_PT_PREPARE_PTE) {
                    tlb_add_unmap_leaf(tlb, virt, level, pte);
                }
            }

            leaves += 1;
        } else {
            ASSERT(pte != 0);
            ASSERT(arch_pt_is_edge(level, pte));

            void *child = arch_pt_edge_target(level, pte);
            size_t ret = do_unmap(child, level - 1, virt, cur, tlb);
            leaves += ret;

            page_t *page = virt_to_page(child);
            page->anon.references -= ret;

            if (page->anon.references == 0) {
                arch_pt_write(table, level, index, 0);
                tlb_add_edge(tlb, virt, true);
                tlb_add_unmap_anon(tlb, page);
            }
        }

        index += 1;
        virt += cur;
        size -= cur;
    } while (size > 0);

    return leaves;
}

static ssize_t do_prepare(void *table, unsigned level, uintptr_t virt, size_t size, tlb_ctx_t *tlb) {
    size_t index = arch_pt_get_index(virt, level);
    ssize_t leaves;

#if !PT_PREPARE_DEBUG
    if (level == 0) {
        leaves = arch_pt_get_index(virt + (size - 1), level) - index + 1;
        virt_to_page(table)->anon.references += leaves;
        return leaves;
    }
#endif

    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    uintptr_t start_virt = virt;

    leaves = 0;

    do {
#if PT_PREPARE_DEBUG
        if (level == 0) {
            ENSURE(arch_pt_read(table, level, index) == 0);
            arch_pt_write(table, level, index, ARCH_PT_PREPARE_PTE);
            index += 1;
            leaves += 1;
            virt += entry_size;
            size -= entry_size;
            continue;
        }
#endif

        pte_t pte = arch_pt_read(table, level, index);
        void *child;

        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        if (pte != 0) {
#if PT_PREPARE_DEBUG
            ASSERT(pte != ARCH_PT_PREPARE_PTE);
#endif
            ASSERT(arch_pt_is_edge(level, pte));
            child = arch_pt_edge_target(level, pte);
        } else {
            child = alloc_table(level - 1);
            if (unlikely(!child)) goto err;
            arch_pt_write(table, level, index, arch_pt_create_edge(level, child));

            if (arch_pt_new_edge_needs_flush()) {
                tlb_add_edge(tlb, virt, false);
            }
        }

        ssize_t ret = do_prepare(child, level - 1, virt, cur, tlb);
        if (unlikely(ret < 0)) goto err;

        index += 1;
        leaves += ret;
        virt += cur;
        size -= cur;
        continue;
    err:
        do_unmap(table, level, start_virt, virt + cur, tlb);
        return -1;
    } while (size > 0);

    virt_to_page(table)->anon.references += leaves;
    return leaves;
}

bool pmap_prepare(pmap_t *pmap, uintptr_t virt, size_t size) {
    ASSERT(arch_pt_get_offset(virt | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(arch_pt_is_canonical(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == is_kernel_address(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == (pmap == NULL));

    if (!pmap) mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, pmap);
    bool ok = do_prepare(pmap ? pmap->table : kernel_page_table, arch_pt_levels() - 1, virt, size, &tlb) >= 0;
    tlb_commit(&tlb);

    migrate_unlock(state);
    if (!pmap) mutex_rel(&kernel_pt_lock);
    return ok;
}

static void do_alloc(void *table, unsigned level, uintptr_t virt, size_t size, int flags, tlb_ctx_t *tlb) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    do {
        if (level == 0) {
#if PT_PREPARE_DEBUG
            ENSURE(arch_pt_read(table, level, index) == ARCH_PT_PREPARE_PTE);
#endif
            page_t *page = pmem_alloc();
            page->anon.references = 1;
            arch_pt_write(table, level, index, arch_pt_create_leaf(level, page_to_phys(page), flags));
            index += 1;
            virt += entry_size;
            size -= entry_size;
            continue;
        }

        pte_t pte = arch_pt_read(table, level, index);
        ASSERT(pte != 0);
#if PT_PREPARE_DEBUG
        ASSERT(pte != ARCH_PT_PREPARE_PTE);
#endif
        ASSERT(arch_pt_is_edge(level, pte));
        void *child = arch_pt_edge_target(level, pte);

        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        do_alloc(child, level - 1, virt, cur, flags, tlb);

        index += 1;
        virt += cur;
        size -= cur;
    } while (size > 0);
}

void pmap_alloc(pmap_t *pmap, uintptr_t virt, size_t size, int flags) {
    ASSERT(arch_pt_get_offset(virt | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(arch_pt_is_canonical(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == is_kernel_address(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == (pmap == NULL));
    ASSERT((flags & ~(PMAP_READABLE | PMAP_WRITABLE | PMAP_EXECUTABLE)) == 0);

    if (!is_kernel_address(virt)) flags |= PMAP_USER;
    flags |= PMAP_ANONYMOUS;

    if (!pmap) mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, pmap);
    do_alloc(pmap ? pmap->table : kernel_page_table, arch_pt_levels() - 1, virt, size, flags, &tlb);
    tlb_commit(&tlb);

    migrate_unlock(state);
    if (!pmap) mutex_rel(&kernel_pt_lock);
}

static void do_map(void *table, unsigned level, uintptr_t virt, uint64_t phys, size_t size, int flags, tlb_ctx_t *tlb) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    do {
        if (level == 0) {
#if PT_PREPARE_DEBUG
            ENSURE(arch_pt_read(table, level, index) == ARCH_PT_PREPARE_PTE);
#endif
            arch_pt_write(table, level, index, arch_pt_create_leaf(level, phys, flags));
            index += 1;
            virt += entry_size;
            phys += entry_size;
            size -= entry_size;
            continue;
        }

        pte_t pte = arch_pt_read(table, level, index);
        ASSERT(pte != 0);
#if PT_PREPARE_DEBUG
        ASSERT(pte != ARCH_PT_PREPARE_PTE);
#endif
        ASSERT(arch_pt_is_edge(level, pte));
        void *child = arch_pt_edge_target(level, pte);

        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        do_map(child, level - 1, virt, phys, cur, flags, tlb);

        index += 1;
        virt += cur;
        phys += cur;
        size -= cur;
    } while (size > 0);
}

void pmap_map(pmap_t *pmap, uintptr_t virt, uint64_t phys, size_t size, int flags) {
    ASSERT(arch_pt_get_offset(virt | phys | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(arch_pt_is_canonical(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == is_kernel_address(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == (pmap == NULL));
    ASSERT(phys < phys + (size - 1));
    ASSERT(phys + (size - 1) <= cpu_max_phys_addr());
    ASSERT((flags & ~(PMAP_READABLE | PMAP_WRITABLE | PMAP_EXECUTABLE | PMAP_CACHE_MASK)) == 0);

    if (!is_kernel_address(virt)) flags |= PMAP_USER;

    if (!pmap) mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, pmap);
    do_map(pmap ? pmap->table : kernel_page_table, arch_pt_levels() - 1, virt, phys, size, flags, &tlb);
    tlb_commit(&tlb);

    migrate_unlock(state);
    if (!pmap) mutex_rel(&kernel_pt_lock);
}

static void do_remap(void *table, unsigned level, uintptr_t virt, size_t size, int flags, tlb_ctx_t *tlb) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    do {
        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        pte_t pte = arch_pt_read(table, level, index);

        if (level == 0) {
#if PT_PREPARE_DEBUG
            ASSERT(pte != 0);
#endif

            if (pte != 0 && !(PT_PREPARE_DEBUG || pte != ARCH_PT_PREPARE_PTE)) {
                pte_t npte = pte;
                bool global = arch_pt_change_permissions(&npte, level, flags);

                if (pte != npte) {
                    arch_pt_write(table, level, index, npte);
                    tlb_add_leaf(tlb, virt, global);
                }
            }
        } else {
            ASSERT(arch_pt_is_edge(level, pte));
            do_remap(arch_pt_edge_target(level, pte), level - 1, virt, cur, flags, tlb);
        }

        index += 1;
        virt += cur;
        size -= cur;
    } while (size > 0);
}

void pmap_remap(pmap_t *pmap, uintptr_t virt, size_t size, int flags) {
    ASSERT(arch_pt_get_offset(virt | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(arch_pt_is_canonical(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == is_kernel_address(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == (pmap == NULL));
    ASSERT((flags & ~(PMAP_READABLE | PMAP_WRITABLE | PMAP_EXECUTABLE)) == 0);

    if (!pmap) mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, pmap);
    do_remap(pmap ? pmap->table : kernel_page_table, arch_pt_levels() - 1, virt, size, flags, &tlb);
    tlb_commit(&tlb);

    migrate_unlock(state);
    if (!pmap) mutex_rel(&kernel_pt_lock);
}

void pmap_move(pmap_t *smap, uintptr_t src, pmap_t *dmap, uintptr_t dest, size_t size) {
    ASSERT(arch_pt_get_offset(src | dest | size) == 0);
    ASSERT(size > 0);
    ASSERT(src < src + (size - 1));
    ASSERT(arch_pt_is_canonical(src));
    ASSERT(arch_pt_is_canonical(src + (size - 1)));
    ASSERT(is_kernel_address(src) == is_kernel_address(src + (size - 1)));
    ASSERT(dest < dest + (size - 1));
    ASSERT(arch_pt_is_canonical(dest));
    ASSERT(arch_pt_is_canonical(dest + (size - 1)));
    ASSERT(is_kernel_address(dest) == is_kernel_address(dest + (size - 1)));
    ASSERT(is_kernel_address(dest) == (dmap == NULL));
    ASSERT((smap != NULL) == (dmap != NULL));
    ASSERT(smap != dmap || src + (size - 1) < dest || src > dest + (size - 1));

    if (!smap) mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, smap);

    void *sroot = smap ? smap->table : kernel_page_table;
    void *droot = dmap ? dmap->table : kernel_page_table;
    unsigned rlevel = arch_pt_levels() - 1;
    size_t advance = 1ul << arch_pt_entry_bits(0);

    while (size != 0) {
        void *table = sroot;
        size_t index = arch_pt_get_index(src, rlevel);
        pte_t pte = arch_pt_read(table, rlevel, index);

        for (unsigned i = rlevel; i > 0; i--) {
            ASSERT(pte != 0);
#if PT_PREPARE_DEBUG
            ASSERT(pte != PT_PREPARE_DEBUG);
#endif
            ASSERT(arch_pt_is_edge(i, pte));

            void *child = arch_pt_edge_target(i, pte);
            page_t *page = virt_to_page(child);

            if (--virt_to_page(child)->anon.references == 0) {
                arch_pt_write(table, i, index, 0);
                tlb_add_edge(&tlb, src, true);
                tlb_add_unmap_anon(&tlb, page);
            }

            table = child;
            index = arch_pt_get_index(src, i - 1);
            pte = arch_pt_read(table, i - 1, index);
        }

#if PT_PREPARE_DEBUG
        ASSERT(pte != 0);
#endif

        if (PT_PREPARE_DEBUG || pte != 0) {
            arch_pt_write(table, 0, index, 0);

            if (!PT_PREPARE_DEBUG || pte != ARCH_PT_PREPARE_PTE) {
                tlb_add_leaf(&tlb, src, true);
            }

            table = droot;
            index = arch_pt_get_index(dest, rlevel);
            pte_t dpte = arch_pt_read(table, rlevel, index);

            for (unsigned i = rlevel; i > 0; i--) {
                ASSERT(dpte != 0);
#if PT_PREPARE_DEBUG
                ASSERT(dpte != ARCH_PT_PREPARE_PTE);
#endif
                ASSERT(arch_pt_is_edge(i, dpte));
                table = arch_pt_edge_target(i, dpte);
                index = arch_pt_get_index(dest, i - 1);
                dpte = arch_pt_read(table, i - 1, index);
            }

#if PT_PREPARE_DEBUG
            ASSERT(dpte == ARCH_PT_PREPARE_PTE);
#endif
            arch_pt_write(table, 0, index, pte);
        }

        src += advance;
        dest += advance;
        size -= advance;
    }

    tlb_commit(&tlb);

    migrate_unlock(state);
    if (!smap) mutex_rel(&kernel_pt_lock);
}

void pmap_unmap(pmap_t *pmap, uintptr_t virt, size_t size) {
    ASSERT(arch_pt_get_offset(virt | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(arch_pt_is_canonical(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == is_kernel_address(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == (pmap == NULL));

    if (!pmap) mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, pmap);
    do_unmap(pmap ? pmap->table : kernel_page_table, arch_pt_levels() - 1, virt, size, &tlb);
    tlb_commit(&tlb);

    migrate_unlock(state);
    if (!pmap) mutex_rel(&kernel_pt_lock);
}

static void do_early_map(
        void *table,
        unsigned level,
        uintptr_t virt,
        uint64_t phys,
        size_t size,
        int flags,
        tlb_ctx_t *tlb
) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    do {
        if (level == 0 || (arch_pt_can_map_direct(level) && ((virt | phys) & entry_mask) == 0 && size >= entry_size)) {
            ASSERT(arch_pt_read(table, level, index) == 0);
            arch_pt_write(table, level, index, arch_pt_create_leaf(level, phys, flags));

            if (arch_pt_new_leaf_needs_flush()) {
                tlb_add_leaf(tlb, virt, false);
            }

            index += 1;
            virt += entry_size;
            phys += entry_size;
            size -= entry_size;
            continue;
        }

        pte_t pte = arch_pt_read(table, level, index);
        void *child;

        if (pte != 0) {
            ASSERT(arch_pt_is_edge(level, pte));
            child = arch_pt_edge_target(level, pte);
        } else {
            child = early_alloc_table(level - 1);
            arch_pt_write(table, level, index, arch_pt_create_edge(level, child));

            if (arch_pt_new_edge_needs_flush()) {
                tlb_add_edge(tlb, virt, false);
            }
        }

        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        do_early_map(child, level - 1, virt, phys, cur, flags, tlb);

        index += 1;
        virt += cur;
        phys += cur;
        size -= cur;
    } while (size != 0);
}

void pmap_early_map(uintptr_t virt, uint64_t phys, size_t size, int flags) {
    ASSERT(arch_pt_get_offset(virt | phys | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(is_kernel_address(virt));
    ASSERT(phys < phys + (size - 1));
    ASSERT(phys + (size - 1) <= cpu_max_phys_addr());
    ASSERT((flags & ~(PMAP_READABLE | PMAP_WRITABLE | PMAP_EXECUTABLE)) == 0);

    mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, NULL);
    do_early_map(kernel_page_table, arch_pt_levels() - 1, virt, phys, size, flags, &tlb);
    tlb_commit(&tlb);

    migrate_unlock(state);
    mutex_rel(&kernel_pt_lock);
}

static void do_early_alloc(void *table, unsigned level, uintptr_t virt, size_t size, int flags, tlb_ctx_t *tlb) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    do {
        if (level == 0) {
            ASSERT(arch_pt_read(table, level, index) == 0);
            arch_pt_write(table, level, index, arch_pt_create_leaf(level, virt_to_phys(early_alloc_page()), flags));

            if (arch_pt_new_leaf_needs_flush()) {
                tlb_add_leaf(tlb, virt, false);
            }

            index += 1;
            virt += entry_size;
            size -= entry_size;
            continue;
        }

        pte_t pte = arch_pt_read(table, level, index);
        void *child;

        if (pte != 0) {
            ASSERT(arch_pt_is_edge(level, pte));
            child = arch_pt_edge_target(level, pte);
        } else {
            child = early_alloc_page();
            memset(child, 0, PAGE_SIZE);
            arch_pt_write(table, level, index, arch_pt_create_edge(level, child));

            if (arch_pt_new_edge_needs_flush()) {
                tlb_add_edge(tlb, virt, false);
            }
        }

        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        do_early_alloc(child, level - 1, virt, cur, flags, tlb);

        index += 1;
        virt += cur;
        size -= cur;
    } while (size != 0);
}

void pmap_early_alloc(uintptr_t virt, size_t size, int flags) {
    ASSERT(arch_pt_get_offset(virt | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(is_kernel_address(virt));
    ASSERT((flags & ~(PMAP_READABLE | PMAP_WRITABLE | PMAP_EXECUTABLE)) == 0);

    mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, NULL);
    do_early_alloc(kernel_page_table, arch_pt_levels() - 1, virt, size, flags, &tlb);
    tlb_commit(&tlb);

    migrate_unlock(state);
    mutex_rel(&kernel_pt_lock);
}

static size_t build_leaf_counts(void *table, unsigned level) {
    size_t leaves = 0;
    size_t max_idx = arch_pt_max_index(level);

    for (size_t index = 0; index <= max_idx; index++) {
        pte_t pte = arch_pt_read(table, level, index);
        if (pte == 0) continue;

        if (level == 0 || !arch_pt_is_edge(level, pte)) {
            leaves += 1;
        } else {
            leaves += build_leaf_counts(arch_pt_edge_target(level, pte), level - 1);
        }
    }

    virt_to_page(table)->anon.references = leaves;
    return leaves;
}

void pmap_early_cleanup(void) {
    mutex_acq(&kernel_pt_lock, 0, false);
    build_leaf_counts(kernel_page_table, arch_pt_levels() - 1);
    mutex_rel(&kernel_pt_lock);
}
