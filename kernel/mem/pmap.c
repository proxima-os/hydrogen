#include "mem/pmap.h"
#include "arch/context.h"
#include "arch/idle.h"
#include "arch/irq.h"
#include "arch/memmap.h"
#include "arch/pmap.h"
#include "cpu/cpudata.h"
#include "cpu/smp.h"
#include "errno.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/memmap.h"
#include "mem/pmem.h"
#include "mem/usercopy.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/mutex.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "string.h"
#include "util/hlist.h"
#include "util/panic.h"
#include "util/printk.h"
#include "util/shlist.h"
#include "util/spinlock.h"
#include <hydrogen/memory.h>
#include <hydrogen/signal.h>
#include <hydrogen/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

    if (pmap) {
        tlb->table = this_cpu_read(pmap.asids)[pmap->asid].table;
        tlb->asid = pmap->asid;
        tlb->current = tlb->table == pmap->table;
    } else {
        tlb->table = kernel_page_table;
        tlb->asid = -1;
        tlb->current = __atomic_load_n(&kernel_pt_switched, __ATOMIC_RELAXED);
    }
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
        if (this_cpu_read(pmap.asids)[ctx->tlb->asid].table == ctx->tlb->pmap->table) {
            arch_pt_flush(ctx->tlb->pmap->table, ctx->tlb->asid);
        }

        __atomic_fetch_sub(&ctx->pending, 1, __ATOMIC_RELEASE);
    } else {
        arch_pt_flush(kernel_page_table, -1);
    }
}

static void anon_free(page_t *page, vmm_t *vmm) {
    if (!page->anon.autounreserve) {
        pmem_free(page);
    } else {
        if (vmm) {
            if (!page->anon.is_page_table) {
                vmm->num_reserved -= 1;
            } else {
                vmm->num_tables -= 1;
            }
        }

        pmem_free_now(page);
    }
}

static void tlb_commit(tlb_ctx_t *tlb, vmm_t *vmm) {
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
        anon_free(page, vmm);
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

INIT_DEFINE_EARLY_AP(memory_ap, pmap_init_switch, INIT_REFERENCE(scheduler_early_ap));

int pmap_init_cpu(cpu_t *cpu) {
    size_t num = arch_pt_max_asid() + 1;
    size_t size = num * sizeof(*cpu->pmap.asids);
    cpu->pmap.asids = vmalloc(size);
    if (unlikely(!cpu->pmap.asids)) return ENOMEM;
    memset(cpu->pmap.asids, 0, size);

    for (size_t i = 0; i < num; i++) {
        cpu->pmap.asids[i].cpu = cpu;
    }

    return 0;
}

void pmap_free_cpu(struct cpu *cpu) {
    vfree(cpu->pmap.asids, (arch_pt_max_asid() + 1) * sizeof(*cpu->pmap.asids));
}

static void *alloc_table(vmm_t *vmm, unsigned level) {
    page_t *page = pmem_alloc_now();
    if (unlikely(!page)) return NULL;
    memset(&page->anon.deref_lock, 0, sizeof(page->anon.deref_lock));
    page->anon.references = 0;
    page->anon.autounreserve = true;
    page->anon.is_page_table = true;
    void *table = page_to_virt(page);
    bool ok = arch_pt_init_table(table, level);

    if (likely(ok)) {
        if (vmm) vmm->num_tables += 1;
        return table;
    } else {
        pmem_free_now(page);
        return NULL;
    }
}

int pmap_create(vmm_t *vmm) {
    static uint64_t next_asid;

    unsigned level = arch_pt_levels() - 1;

    memset(&vmm->pmap, 0, sizeof(vmm->pmap));
    if (unlikely(!(vmm->pmap.table = alloc_table(vmm, level)))) return ENOMEM;
    vmm->pmap.asid = __atomic_fetch_add(&next_asid, 1, __ATOMIC_RELAXED) % (arch_pt_max_asid() + 1);

    size_t min_idx = arch_pt_get_index(arch_pt_max_user_addr(), level) + 1;
    size_t max_idx = arch_pt_max_index(level);

    while (min_idx <= max_idx) {
        arch_pt_write(vmm->pmap.table, level, min_idx, arch_pt_read(kernel_page_table, level, min_idx));
        min_idx += 1;
    }

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

    if (old != NULL && old->asid == target->asid) {
        if ((uintptr_t)old < (uintptr_t)target) {
            spin_acq_noirq(&old->cpus_lock);
            spin_acq_noirq(&target->cpus_lock);
        } else {
            spin_acq_noirq(&target->cpus_lock);
            spin_acq_noirq(&old->cpus_lock);
        }

        hlist_remove(&old->cpus, &asid->node);

        // this has to be done while both old->cpus_lock and target->cpus_lock is held
        //  if old->cpus_lock isn't held, destruction might free the tables before we're ready
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

void pmap_prepare_destroy(pmap_t *pmap) {
    // ensure no cpus are using this pmap
    preempt_state_t state = preempt_lock();
    spin_acq_noirq(&pmap->cpus_lock);

    cpu_t *cur_cpu = get_current_cpu();

    for (;;) {
        pmap_asid_data_t *asid = HLIST_HEAD(pmap->cpus, pmap_asid_data_t, node);
        if (!asid) break;
        ASSERT(asid->table == pmap->table);

        if (asid->cpu->pmap.current == pmap) {
            if (asid->cpu == cur_cpu) {
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
}

static size_t do_destroy_range(vmm_t *vmm, void *table, unsigned level, uintptr_t virt, size_t size) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    size_t leaves = 0;

    do {
        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        pte_t pte = arch_pt_read(table, level, index);

        if (level == 0) {
            ASSERT(pte != 0);
#if HYDROGEN_ASSERTIONS
            arch_pt_write(table, leaves, index, 0);
#endif

            if (pte != ARCH_PT_PREPARE_PTE) {
                int flags = arch_pt_get_leaf_flags(level, pte);

                if (flags & PMAP_ANONYMOUS) {
                    page_t *page = phys_to_page(arch_pt_leaf_target(level, pte));
                    mutex_acq(&page->anon.deref_lock, 0, false);
                    size_t refs = __atomic_fetch_sub(&page->anon.references, 1, __ATOMIC_ACQ_REL);
                    mutex_rel(&page->anon.deref_lock);

                    if (refs == 1) {
                        anon_free(page, vmm);
                    }
                }
            }

            leaves += 1;
        } else {
            ASSERT(pte != 0);
            ASSERT(pte != ARCH_PT_PREPARE_PTE);
            ASSERT(arch_pt_is_edge(level, pte));

            void *child = arch_pt_edge_target(level, pte);
            size_t cleaf = do_destroy_range(vmm, child, level - 1, virt, cur);
            page_t *cpage = virt_to_page(child);
            cpage->anon.references -= cleaf;

            if (cpage->anon.references == 0) {
#if HYDROGEN_ASSERTIONS
                arch_pt_write(table, level, index, 0);
#endif
                anon_free(cpage, vmm);
            }

            leaves += cleaf;
        }

        index += 1;
        virt += cur;
        size -= cur;
    } while (size > 0);

    return leaves;
}

void pmap_destroy_range(vmm_t *vmm, uintptr_t virt, size_t size) {
    ASSERT(vmm != NULL);
    ASSERT(arch_pt_get_offset(virt | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(arch_pt_is_canonical(virt + (size - 1)));
    ASSERT(!is_kernel_address(virt + (size - 1)));

    UNUSED size_t leaves = do_destroy_range(vmm, vmm->pmap.table, arch_pt_levels() - 1, virt, size);
#if HYDROGEN_ASSERTIONS
    virt_to_page(vmm->pmap.table)->anon.references -= leaves;
#endif
}

void pmap_finish_destruction(vmm_t *vmm) {
#if HYDROGEN_ASSERTIONS
    {
        unsigned level = arch_pt_levels() - 1;
        size_t max = arch_pt_get_index(arch_pt_max_user_addr(), level);

        for (size_t i = 0; i <= max; i++) {
            ENSURE(arch_pt_read(vmm->pmap.table, level, i) == 0);
        }

        ENSURE(virt_to_page(vmm->pmap.table)->anon.references == 0);
    }
#endif

    anon_free(virt_to_page(vmm->pmap.table), vmm);
}

static void tlb_add_unmap_leaf(tlb_ctx_t *tlb, uintptr_t addr, unsigned level, pte_t pte) {
    tlb_add_leaf(tlb, addr, true);

    int flags = arch_pt_get_leaf_flags(level, pte);

    if (flags & PMAP_ANONYMOUS) {
        page_t *page = phys_to_page(arch_pt_leaf_target(level, pte));
        mutex_acq(&page->anon.deref_lock, 0, false);
        size_t refs = __atomic_fetch_sub(&page->anon.references, 1, __ATOMIC_ACQ_REL);
        mutex_rel(&page->anon.deref_lock);

        if (refs == 1) shlist_insert_head(&tlb->free_queue, &page->anon.free_node);
    }
}

static bool do_prepare_alloc(vmm_t *vmm, void *table, unsigned level, uintptr_t virt, size_t size, tlb_ctx_t *tlb) {
    if (level == 0) return true;

    uintptr_t start_virt = virt;
    size_t start_index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    size_t index = start_index;

    do {
        pte_t pte = arch_pt_read(table, level, index);
        void *child;

        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        if (pte != 0) {
            ASSERT(pte != ARCH_PT_PREPARE_PTE);
            ASSERT(arch_pt_is_edge(level, pte));
            child = arch_pt_edge_target(level, pte);
        } else {
            child = alloc_table(vmm, level - 1);
            if (unlikely(!child)) goto err;
            arch_pt_write(table, level, index, arch_pt_create_edge(level, child));

            if (arch_pt_new_edge_needs_flush()) {
                tlb_add_edge(tlb, virt, false);
            }
        }

        index += 1;

        if (unlikely(!do_prepare_alloc(vmm, child, level - 1, virt, cur, tlb))) goto err;

        virt += cur;
        size -= cur;
        continue;
    err:
        virt = start_virt & ~entry_mask;

        for (size_t i = start_index; i < index; i++, virt += entry_size) {
            pte = arch_pt_read(table, level, i);
            ASSERT(pte != 0);
            ASSERT(pte != ARCH_PT_PREPARE_PTE);
            ASSERT(arch_pt_is_edge(level, pte));

            page_t *page = virt_to_page(arch_pt_edge_target(level, pte));

            if (page->anon.references == 0) {
                // newly allocated by this call, remove it
                arch_pt_write(table, level, index, 0);
                tlb_add_edge(tlb, virt, true);
                shlist_insert_head(&tlb->free_queue, &page->anon.free_node);
            }
        }

        return false;
    } while (size > 0);

    return true;
}

static size_t do_prepare_fill(vmm_t *vmm, void *table, unsigned level, uintptr_t virt, size_t size, tlb_ctx_t *tlb) {
    size_t index = arch_pt_get_index(virt, level);
    size_t leaves = 0;

    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    do {
        pte_t pte = arch_pt_read(table, level, index);

        if (level == 0) {
            if (pte == 0) {
                arch_pt_write(table, level, index, ARCH_PT_PREPARE_PTE);
                leaves += 1;
            }

            index += 1;
            virt += entry_size;
            size -= entry_size;
            continue;
        }

        ASSERT(pte != 0);
        ASSERT(pte != ARCH_PT_PREPARE_PTE);
        ASSERT(arch_pt_is_edge(level, pte));

        void *child = arch_pt_edge_target(level, pte);

        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        size_t ret = do_prepare_fill(vmm, child, level - 1, virt, cur, tlb);

        index += 1;
        leaves += ret;
        virt += cur;
        size -= cur;
    } while (size > 0);

    virt_to_page(table)->anon.references += leaves;
    return leaves;
}

bool pmap_prepare(vmm_t *vmm, uintptr_t virt, size_t size) {
    ASSERT(arch_pt_get_offset(virt | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(arch_pt_is_canonical(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == is_kernel_address(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == (vmm == NULL));

    if (!vmm) mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, vmm ? &vmm->pmap : NULL);

    bool ok = do_prepare_alloc(vmm, vmm ? vmm->pmap.table : kernel_page_table, arch_pt_levels() - 1, virt, size, &tlb);

    if (ok) {
        do_prepare_fill(vmm, vmm ? vmm->pmap.table : kernel_page_table, arch_pt_levels() - 1, virt, size, &tlb);
    }

    tlb_commit(&tlb, vmm);

    migrate_unlock(state);
    if (!vmm) mutex_rel(&kernel_pt_lock);
    return ok;
}

static void do_alloc(void *table, unsigned level, uintptr_t virt, size_t size, int flags, tlb_ctx_t *tlb) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    do {
        if (level == 0) {
            ASSERT(arch_pt_read(table, level, index) == ARCH_PT_PREPARE_PTE);
            page_t *page = pmem_alloc();
            memset(&page->anon.deref_lock, 0, sizeof(page->anon.deref_lock));
            page->anon.references = 1;
            page->anon.autounreserve = false;
            page->anon.is_page_table = false;
            arch_pt_write(table, level, index, arch_pt_create_leaf(level, page_to_phys(page), flags));
            index += 1;
            virt += entry_size;
            size -= entry_size;
            continue;
        }

        pte_t pte = arch_pt_read(table, level, index);
        ASSERT(pte != 0);
        ASSERT(pte != ARCH_PT_PREPARE_PTE);
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

void pmap_alloc(vmm_t *vmm, uintptr_t virt, size_t size, int flags) {
    ASSERT(arch_pt_get_offset(virt | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(arch_pt_is_canonical(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == is_kernel_address(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == (vmm == NULL));
    ASSERT((flags & ~(PMAP_READABLE | PMAP_WRITABLE | PMAP_EXECUTABLE)) == 0);

    if (!is_kernel_address(virt)) flags |= PMAP_USER;
    flags |= PMAP_ANONYMOUS;

    if (!vmm) mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, vmm ? &vmm->pmap : NULL);
    do_alloc(vmm ? vmm->pmap.table : kernel_page_table, arch_pt_levels() - 1, virt, size, flags, &tlb);
    tlb_commit(&tlb, vmm);

    migrate_unlock(state);
    if (!vmm) mutex_rel(&kernel_pt_lock);
}

static void do_map(void *table, unsigned level, uintptr_t virt, uint64_t phys, size_t size, int flags, tlb_ctx_t *tlb) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    do {
        if (level == 0) {
            ASSERT(arch_pt_read(table, level, index) == ARCH_PT_PREPARE_PTE);
            arch_pt_write(table, level, index, arch_pt_create_leaf(level, phys, flags));
            index += 1;
            virt += entry_size;
            phys += entry_size;
            size -= entry_size;
            continue;
        }

        pte_t pte = arch_pt_read(table, level, index);
        ASSERT(pte != 0);
        ASSERT(pte != ARCH_PT_PREPARE_PTE);
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

void pmap_map(vmm_t *vmm, uintptr_t virt, uint64_t phys, size_t size, int flags) {
    ASSERT(arch_pt_get_offset(virt | phys | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(arch_pt_is_canonical(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == is_kernel_address(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == (vmm == NULL));
    ASSERT(phys < phys + (size - 1));
    ASSERT(phys + (size - 1) <= cpu_max_phys_addr());
    ASSERT((flags & ~(PMAP_READABLE | PMAP_WRITABLE | PMAP_EXECUTABLE | PMAP_CACHE_MASK)) == 0);

    if (!is_kernel_address(virt)) flags |= PMAP_USER;

    if (!vmm) mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, vmm ? &vmm->pmap : NULL);
    do_map(vmm ? vmm->pmap.table : kernel_page_table, arch_pt_levels() - 1, virt, phys, size, flags, &tlb);
    tlb_commit(&tlb, vmm);

    migrate_unlock(state);
    if (!vmm) mutex_rel(&kernel_pt_lock);
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
            ASSERT(pte != 0);
            ASSERT(table != kernel_page_table);

            if (pte != ARCH_PT_PREPARE_PTE) {
                int new_flags = flags;

                if (arch_pt_get_leaf_flags(level, pte) & PMAP_COPY_ON_WRITE) new_flags &= ~PMAP_WRITABLE;

                pte_t npte = pte;
                bool global = arch_pt_change_permissions(&npte, level, new_flags);

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

void pmap_remap(vmm_t *vmm, uintptr_t virt, size_t size, int flags) {
    ASSERT(arch_pt_get_offset(virt | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(arch_pt_is_canonical(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == is_kernel_address(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == (vmm == NULL));
    ASSERT((flags & ~(PMAP_READABLE | PMAP_WRITABLE | PMAP_EXECUTABLE)) == 0);

    if (!vmm) mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, vmm ? &vmm->pmap : NULL);
    do_remap(vmm ? vmm->pmap.table : kernel_page_table, arch_pt_levels() - 1, virt, size, flags, &tlb);
    tlb_commit(&tlb, vmm);

    migrate_unlock(state);
    if (!vmm) mutex_rel(&kernel_pt_lock);
}

static void do_clone(void *src, void *dst, unsigned level, uintptr_t virt, size_t size, bool cow, tlb_ctx_t *tlb) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    do {
        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        pte_t pte = arch_pt_read(src, level, index);

        if (level == 0) {
            ASSERT(pte != 0);
            ASSERT(arch_pt_read(dst, level, index) == ARCH_PT_PREPARE_PTE);

            if (pte != ARCH_PT_PREPARE_PTE) {
                int flags = arch_pt_get_leaf_flags(level, pte);

                if (cow) {
                    int orig_flags = flags;
                    flags = (flags & ~PMAP_WRITABLE) | PMAP_COPY_ON_WRITE;

                    if (orig_flags != flags) {
                        pte = arch_pt_create_leaf(level, arch_pt_leaf_target(level, pte), flags);
                        arch_pt_write(src, level, index, pte);

                        if (orig_flags & PMAP_WRITABLE) {
                            tlb_add_leaf(tlb, virt, true);
                        }
                    }
                }

                if (flags & PMAP_ANONYMOUS) {
                    page_t *page = phys_to_page(arch_pt_leaf_target(level, pte));
                    __atomic_fetch_add(&page->anon.references, 1, __ATOMIC_ACQUIRE);
                }

                arch_pt_write(dst, level, index, pte);
            }
        } else {
            pte_t dpte = arch_pt_read(dst, level, index);

            ASSERT(pte != 0);
            ASSERT(dpte != 0);
            ASSERT(pte != ARCH_PT_PREPARE_PTE);
            ASSERT(dpte != ARCH_PT_PREPARE_PTE);
            ASSERT(arch_pt_is_edge(level, pte));
            ASSERT(arch_pt_is_edge(level, dpte));

            do_clone(arch_pt_edge_target(level, pte), arch_pt_edge_target(level, dpte), level - 1, virt, cur, cow, tlb);
        }

        index += 1;
        virt += cur;
        size -= cur;
    } while (size > 0);
}

void pmap_clone(vmm_t *vmm, vmm_t *dest, uintptr_t virt, size_t size, bool cow) {
    ASSERT(vmm != NULL);
    ASSERT(dest != NULL);
    ASSERT(arch_pt_get_offset(virt | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(arch_pt_is_canonical(virt + (size - 1)));
    ASSERT(!is_kernel_address(virt + (size - 1)));

    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, vmm ? &vmm->pmap : NULL);
    do_clone(vmm->pmap.table, dest->pmap.table, arch_pt_levels() - 1, virt, size, cow, &tlb);
    tlb_commit(&tlb, vmm);

    migrate_unlock(state);
}

void pmap_move(vmm_t *svmm, uintptr_t src, vmm_t *dvmm, uintptr_t dest, size_t size) {
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
    ASSERT(is_kernel_address(dest) == (dvmm == NULL));
    ASSERT((svmm != NULL) == (dvmm != NULL));
    ASSERT(svmm != dvmm || src + (size - 1) < dest || src > dest + (size - 1));

    if (!svmm) mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, svmm ? &svmm->pmap : NULL);

    void *sroot = svmm ? svmm->pmap.table : kernel_page_table;
    void *droot = dvmm ? dvmm->pmap.table : kernel_page_table;
    unsigned rlevel = arch_pt_levels() - 1;
    size_t advance = 1ul << arch_pt_entry_bits(0);

    while (size != 0) {
        void *table = sroot;
        size_t index = arch_pt_get_index(src, rlevel);
        pte_t pte = arch_pt_read(table, rlevel, index);

        for (unsigned i = rlevel; i > 0; i--) {
            ASSERT(pte != 0);
            ASSERT(pte != ARCH_PT_PREPARE_PTE);
            ASSERT(arch_pt_is_edge(i, pte));

            void *child = arch_pt_edge_target(i, pte);
            page_t *page = virt_to_page(child);

            if (--virt_to_page(child)->anon.references == 0) {
                arch_pt_write(table, i, index, 0);
                tlb_add_edge(&tlb, src, true);
                shlist_insert_head(&tlb.free_queue, &page->anon.free_node);
            }

            table = child;
            index = arch_pt_get_index(src, i - 1);
            pte = arch_pt_read(table, i - 1, index);
        }

        ASSERT(pte != 0);

        arch_pt_write(table, 0, index, 0);

        if (pte != ARCH_PT_PREPARE_PTE) {
            tlb_add_leaf(&tlb, src, true);
        }

        table = droot;
        index = arch_pt_get_index(dest, rlevel);
        pte_t dpte = arch_pt_read(table, rlevel, index);

        for (unsigned i = rlevel; i > 0; i--) {
            ASSERT(dpte != 0);
            ASSERT(dpte != ARCH_PT_PREPARE_PTE);
            ASSERT(arch_pt_is_edge(i, dpte));
            table = arch_pt_edge_target(i, dpte);
            index = arch_pt_get_index(dest, i - 1);
            dpte = arch_pt_read(table, i - 1, index);
        }

        ASSERT(dpte == ARCH_PT_PREPARE_PTE);
        arch_pt_write(table, 0, index, pte);

        src += advance;
        dest += advance;
        size -= advance;
    }

    tlb_commit(&tlb, svmm);

    migrate_unlock(state);
    if (!svmm) mutex_rel(&kernel_pt_lock);
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

        if (level == 0 || !arch_pt_is_edge(level, pte)) {
            ASSERT(pte != 0);
            ASSERT(table != kernel_page_table);

            arch_pt_write(table, level, index, 0);

            if (pte != ARCH_PT_PREPARE_PTE) {
                tlb_add_unmap_leaf(tlb, virt, level, pte);
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

            if (page->anon.references == 0 && table != kernel_page_table) {
                arch_pt_write(table, level, index, 0);
                tlb_add_edge(tlb, virt, true);
                shlist_insert_head(&tlb->free_queue, &page->anon.free_node);
            }
        }

        index += 1;
        virt += cur;
        size -= cur;
    } while (size > 0);

    return leaves;
}

void pmap_unmap(vmm_t *vmm, uintptr_t virt, size_t size) {
    ASSERT(arch_pt_get_offset(virt | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(arch_pt_is_canonical(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == is_kernel_address(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == (vmm == NULL));

    if (!vmm) mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, vmm ? &vmm->pmap : NULL);
    void *table = vmm ? vmm->pmap.table : kernel_page_table;
    size_t leaves = do_unmap(table, arch_pt_levels() - 1, virt, size, &tlb);
    virt_to_page(table)->anon.references -= leaves;
    tlb_commit(&tlb, vmm);

    migrate_unlock(state);
    if (!vmm) mutex_rel(&kernel_pt_lock);
}

static void do_rmmap(void *table, unsigned level, uintptr_t virt, size_t size, tlb_ctx_t *tlb) {
    size_t index = arch_pt_get_index(virt, level);
    size_t entry_size = 1ul << arch_pt_entry_bits(level);
    size_t entry_mask = entry_size - 1;

    do {
        size_t cur = entry_size - (virt & entry_mask);
        if (cur > size) cur = size;

        pte_t pte = arch_pt_read(table, level, index);

        if (level == 0 || !arch_pt_is_edge(level, pte)) {
            ASSERT(pte != 0);
            ASSERT(table != kernel_page_table);

            if (pte != ARCH_PT_PREPARE_PTE) {
                arch_pt_write(table, level, index, ARCH_PT_PREPARE_PTE);
                tlb_add_unmap_leaf(tlb, virt, level, pte);
            }
        } else {
            ASSERT(pte != 0);
            ASSERT(arch_pt_is_edge(level, pte));

            do_rmmap(arch_pt_edge_target(level, pte), level - 1, virt, cur, tlb);
        }

        index += 1;
        virt += cur;
        size -= cur;
    } while (size > 0);
}

void pmap_rmmap(struct vmm *vmm, uintptr_t virt, size_t size) {
    ASSERT(arch_pt_get_offset(virt | size) == 0);
    ASSERT(size > 0);
    ASSERT(virt < virt + (size - 1));
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(arch_pt_is_canonical(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == is_kernel_address(virt + (size - 1)));
    ASSERT(is_kernel_address(virt) == (vmm == NULL));

    if (!vmm) mutex_acq(&kernel_pt_lock, 0, false);
    migrate_state_t state = migrate_lock();

    tlb_ctx_t tlb;
    tlb_init(&tlb, vmm ? &vmm->pmap : NULL);
    do_rmmap(vmm ? vmm->pmap.table : kernel_page_table, arch_pt_levels() - 1, virt, size, &tlb);
    tlb_commit(&tlb, vmm);

    migrate_unlock(state);
    if (!vmm) mutex_rel(&kernel_pt_lock);
}

typedef struct {
    size_t root_index;
    pte_t root_pte;
    void *table;
    unsigned level;
    size_t index;
    pte_t pte;
} get_pte_result_t;

static bool get_pte(get_pte_result_t *out, void *root, uintptr_t address) {
    out->table = root;
    out->level = arch_pt_levels() - 1;
    out->index = arch_pt_get_index(address, out->level);
    out->pte = arch_pt_read(root, out->level, out->index);

    out->root_index = out->index;
    out->root_pte = out->pte;

    for (;;) {
        if (unlikely(out->pte == 0)) return false;
        if (unlikely(out->pte == ARCH_PT_PREPARE_PTE)) return false;
        if (out->level == 0 || !arch_pt_is_edge(out->level, out->pte)) return true;

        out->table = arch_pt_edge_target(out->level, out->pte);
        out->level -= 1;
        out->index = arch_pt_get_index(address, out->level);
        out->pte = arch_pt_read(out->table, out->level, out->index);
    }
}

struct page *pmap_get_mapping(struct vmm *vmm, uintptr_t virt) {
    ASSERT(vmm != NULL);
    ASSERT(arch_pt_is_canonical(virt));
    ASSERT(!is_kernel_address(virt));

    get_pte_result_t result = {};
    if (unlikely(!get_pte(&result, vmm->pmap.table, virt))) return NULL;

    int flags = arch_pt_get_leaf_flags(result.level, result.pte);
    if (unlikely((flags & PMAP_ANONYMOUS) == 0)) return NULL;

    return phys_to_page(arch_pt_leaf_target(result.level, result.pte));
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
    tlb_commit(&tlb, NULL);

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
    tlb_commit(&tlb, NULL);

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

static const char *type_to_string(pmap_fault_type_t type) {
    switch (type) {
    case PMAP_FAULT_READ: return "read";
    case PMAP_FAULT_WRITE: return "write";
    case PMAP_FAULT_EXECUTE: return "execute";
    default: UNREACHABLE();
    }
}

static bool is_access_allowed(unsigned level, pte_t pte, pmap_fault_type_t type) {
    unsigned flags = arch_pt_get_leaf_flags(level, pte);

    switch (type) {
    case PMAP_FAULT_READ: return flags & PMAP_READABLE;
    case PMAP_FAULT_WRITE: return flags & PMAP_WRITABLE;
    case PMAP_FAULT_EXECUTE: return flags & PMAP_EXECUTABLE;
    default: UNREACHABLE();
    }
}

static void user_fault_fail(
    arch_context_t *context,
    uintptr_t pc,
    uintptr_t address,
    unsigned flags,
    int signal,
    int code,
    int error
) {
    if ((flags & PMAP_FAULT_USER) == 0) {
        ASSERT(arch_is_user_copy(pc));
        arch_user_copy_fail(context, error);
        return;
    }

    printk(
        "pmap: sending signal %d to thread %d (process %d) due to fault on address 0x%Z (code: %d, error: %d)\n",
        signal,
        current_thread->pid->id,
        current_thread->process->pid->id,
        address,
        code,
        error
    );

    __siginfo_t sig = {
        .__signo = __SIGSEGV,
        .__code = code,
        .__errno = error,
        .__data.__sigsegv.__address = (void *)address,
    };
    queue_signal(
        current_thread->process,
        &current_thread->sig_target,
        &sig,
        QUEUE_SIGNAL_FORCE,
        &current_thread->fault_sig
    );
}

static bool region_allows_access(vmm_region_t *region, pmap_fault_type_t type) {
    switch (type) {
    case PMAP_FAULT_READ: return region->flags & HYDROGEN_MEM_READ;
    case PMAP_FAULT_WRITE: return region->flags & HYDROGEN_MEM_WRITE;
    case PMAP_FAULT_EXECUTE: return region->flags & HYDROGEN_MEM_EXEC;
    default: UNREACHABLE();
    }
}

static page_t *alloc_page_for_user_mapping(vmm_t *vmm, vmm_region_t *region) {
    static uint64_t next_id;

    page_t *page;

    if ((region->flags & HYDROGEN_MEM_LAZY_RESERVE) == 0) {
        page = pmem_alloc();
        page->anon.autounreserve = false;
    } else {
        page = pmem_alloc_now();
        if (unlikely(!page)) return NULL;
        page->anon.autounreserve = true;
        vmm->num_reserved += 1;
    }

    memset(&page->anon.deref_lock, 0, sizeof(page->anon.deref_lock));
    page->anon.references = 1;
    page->anon.id = __atomic_fetch_add(&next_id, 1, __ATOMIC_RELAXED);
    page->anon.is_page_table = false;
    return page;
}

static void create_new_user_mapping(
    arch_context_t *context,
    vmm_t *vmm,
    uintptr_t pc,
    uintptr_t address,
    pmap_fault_type_t type,
    unsigned flags,
    get_pte_result_t *result
) {
    vmm_region_t *region = vmm_get_region(vmm, address);
    if (unlikely(!region)) return user_fault_fail(context, pc, address, flags, __SIGSEGV, __SEGV_MAPERR, EFAULT);
    if (unlikely(!region_allows_access(region, type))) {
        return user_fault_fail(context, pc, address, flags, __SIGSEGV, __SEGV_ACCERR, EFAULT);
    }

    uint64_t target;
    int pte_flags = PMAP_USER | vmm_to_pmap_flags(region->flags);

    if (region->object == NULL) {
        page_t *page = alloc_page_for_user_mapping(vmm, region);
        if (unlikely(!page)) return user_fault_fail(context, pc, address, flags, __SIGBUS, __BUS_OBJERR, ENOMEM);
        memset(page_to_virt(page), 0, PAGE_SIZE);
        target = page_to_phys(page);

        pte_flags |= PMAP_ANONYMOUS;
    } else {
        const mem_object_ops_t *ops = (const mem_object_ops_t *)region->object->base.ops;
        if (unlikely(!ops->get_page)) {
            return user_fault_fail(context, pc, address, flags, __SIGBUS, __BUS_ADRERR, ENXIO);
        }

        hydrogen_ret_t ret = ops->get_page(
            region->object,
            region,
            (region->offset + (address - region->head)) >> PAGE_SHIFT,
            NULL,
            type == PMAP_FAULT_WRITE
        );
        if (unlikely(ret.error)) {
            return user_fault_fail(
                context,
                pc,
                address,
                flags,
                __SIGBUS,
                ret.error == ENXIO ? __BUS_ADRERR : __BUS_OBJERR,
                ret.error
            );
        }
        target = page_to_phys(ret.pointer);

        if ((region->flags & HYDROGEN_MEM_SHARED) == 0) {
            pte_flags &= ~PMAP_WRITABLE;
            pte_flags |= PMAP_COPY_ON_WRITE;
        }
    }

    pte_t pte = arch_pt_create_leaf(result->level, target, pte_flags);
    arch_pt_write(result->table, result->level, result->index, pte);

    if (arch_pt_new_leaf_needs_flush()) {
        arch_pt_flush_leaf(address, vmm->pmap.table, vmm->pmap.asid, false, true);
    }
}

static int copy_mapping(vmm_t *vmm, vmm_region_t *region, page_t **out, uint64_t source, int flags) {
    ASSERT(flags & PMAP_COPY_ON_WRITE);

    if ((flags & PMAP_ANONYMOUS) == 0) {
        page_t *page = alloc_page_for_user_mapping(vmm, region);
        if (unlikely(!page)) return ENOMEM;
        memcpy(page_to_virt(page), phys_to_virt(source), PAGE_SIZE);

        *out = page;
        return 0;
    }

    page_t *src = phys_to_page(source);

    if (__atomic_load_n(&src->anon.references, __ATOMIC_ACQUIRE) == 1) {
        *out = src;
        return 0;
    }

    // CoW requires the reference count to have a lock, because it must not
    // allocate a new page if the old one only has one reference; there would
    // not be a reservation for this allocation. Checking for this beforehand
    // without a lock is not sufficient, since another address space might get
    // rid of its reference before we've finished copying and dereferenced.
    // Doing the dereference beforehand wouldn't work either, since then another
    // address space might free the page before we've finished copying. Normally
    // this would be solved by making the copy fallible and rechecking afterwards,
    // but we can't make the copy fallible, because then we'd potentially allocate
    // without a reservation.
    mutex_acq(&src->anon.deref_lock, 0, false);

    // Still need to read atomically: deref_lock only protects from derefs,
    // new refs are allowed to be added without taking a lock.
    if (__atomic_load_n(&src->anon.references, __ATOMIC_ACQUIRE) == 1) {
        mutex_rel(&src->anon.deref_lock);
        *out = src;
        return 0;
    }

    page_t *dst = pmem_alloc();
    memset(&dst->anon.deref_lock, 0, sizeof(dst->anon.deref_lock));
    dst->anon.references = 1;
    dst->anon.autounreserve = src->anon.autounreserve;
    dst->anon.is_page_table = false;
    memcpy(page_to_virt(dst), page_to_virt(src), PAGE_SIZE);

    UNUSED size_t old = __atomic_fetch_sub(&src->anon.references, 1, __ATOMIC_ACQ_REL);
    ASSERT(old != 1);
    mutex_rel(&src->anon.deref_lock);

    *out = dst;
    return 0;
}

static void do_handle_user_fault(
    arch_context_t *context,
    vmm_t *vmm,
    uintptr_t pc,
    uintptr_t address,
    pmap_fault_type_t type,
    unsigned flags
) {
    get_pte_result_t result = {};

    if (unlikely(!get_pte(&result, vmm->pmap.table, address))) {
        if (unlikely(result.level != 0)) {
            return user_fault_fail(context, pc, address, flags, __SIGSEGV, __SEGV_MAPERR, EFAULT);
        }

        if (unlikely(result.pte != ARCH_PT_PREPARE_PTE)) {
            return user_fault_fail(context, pc, address, flags, __SIGSEGV, __SEGV_MAPERR, EFAULT);
        }

        return create_new_user_mapping(context, vmm, pc, address, type, flags, &result);
    }

    if (likely(is_access_allowed(result.level, result.pte, type))) {
        migrate_state_t state = migrate_lock();

        if (arch_pt_new_edge_needs_flush()) {
            arch_pt_flush_edge(address, vmm->pmap.table, vmm->pmap.asid, false, true);
        }

        arch_pt_flush_leaf(address, vmm->pmap.table, vmm->pmap.asid, false, true);

        migrate_unlock(state);
        return;
    }

    int pte_flags = arch_pt_get_leaf_flags(result.level, result.pte);

    if (likely(type == PMAP_FAULT_WRITE) && likely(pte_flags & PMAP_COPY_ON_WRITE)) {
        vmm_region_t *region = vmm_get_region(vmm, address);
        ASSERT(region != NULL);

        if (unlikely((region->flags & HYDROGEN_MEM_WRITE) == 0)) {
            return user_fault_fail(context, pc, address, flags, __SIGSEGV, __SEGV_ACCERR, EFAULT);
        }

        page_t *new_page;
        int error = copy_mapping(vmm, region, &new_page, arch_pt_leaf_target(result.level, result.pte), pte_flags);
        if (unlikely(error)) return user_fault_fail(context, pc, address, flags, __SIGBUS, __BUS_OBJERR, error);

        pte_flags &= ~PMAP_COPY_ON_WRITE;
        pte_flags |= PMAP_ANONYMOUS | PMAP_WRITABLE;

        migrate_state_t state = migrate_lock();

        // We can't just insert the new entry immediately, since that causes a race condition with >=3 CPUs that allows
        // one CPU to read data from the old page after another CPU has already successfully written to the new page:
        // 1. CPU2 reads from the page, putting the read-only mapping into CPU2's TLB, and spins until a flag is set.
        // 2. CPU0 triggers the page fault. The page is copied and the new entry is inserted into the page table, but
        //    the shootdown hasn't been triggered yet.
        // 3. CPU1 writes to the page. It doesn't have the mapping in its TLB, so it fetches the new entry and writes to
        //    the page without causing a fault. It then sets the flag CPU2 is waiting on.
        // 4. CPU2 notices the flag is set, and reads the field CPU1 wrote. It still has the old read-only entry in its
        //    TLB, so it reads the old value in the read-only page, not the value CPU1 wrote.
        // 5. Only now does CPU0 trigger the shootdown, but it's too late.
        // This can be fixed by unmapping the page and shooting it down before inserting the new entry. If any other CPU
        // tries to access the page before the new entry is inserted, it will cause a page fault that tries to acquire
        // the address space lock. By the time it acquires the lock, the new entry will have been inserted, so the lazy
        // TLB code will treat it as a spurious page fault and userspace will retry the access.
        tlb_ctx_t tlb;
        tlb_init(&tlb, &vmm->pmap);
        arch_pt_write(result.table, result.level, result.index, 0);
        tlb_add_leaf(&tlb, address, true);
        tlb_commit(&tlb, vmm);

        arch_pt_write(
            result.table,
            result.level,
            result.index,
            arch_pt_create_leaf(result.level, page_to_phys(new_page), pte_flags)
        );

        if (arch_pt_new_leaf_needs_flush()) {
            arch_pt_flush_leaf(address, vmm->pmap.table, vmm->pmap.asid, false, true);
        }

        migrate_unlock(state);
        return;
    }

    user_fault_fail(context, pc, address, flags, __SIGSEGV, __SEGV_ACCERR, EFAULT);
}

static void handle_user_fault(
    arch_context_t *context,
    uintptr_t pc,
    uintptr_t address,
    pmap_fault_type_t type,
    unsigned flags
) {
    if (!arch_pt_is_canonical(address) || is_kernel_address(address)) {
        return user_fault_fail(context, pc, address, flags, __SIGSEGV, __SEGV_MAPERR, EFAULT);
    }

    vmm_t *vmm = current_thread->vmm;
    ASSERT(vmm != NULL);
    ASSERT(&vmm->pmap == this_cpu_read_tl(pmap.current));

    rmutex_acq(&vmm->lock, 0, false);
    do_handle_user_fault(context, vmm, pc, address, type, flags);
    rmutex_rel(&vmm->lock);
}

void pmap_handle_page_fault(
    arch_context_t *context,
    uintptr_t pc,
    uintptr_t address,
    pmap_fault_type_t type,
    unsigned flags
) {
    if (flags & PMAP_FAULT_USER) return handle_user_fault(context, pc, address, type, flags);

    if (!is_kernel_address(address)) {
        if (arch_is_user_copy(pc)) return handle_user_fault(context, pc, address, type, flags);

        panic(
            "kernel code tried to %s user memory at 0x%Z (pc: 0x%Z, flags: %u)",
            type_to_string(type),
            address,
            pc,
            flags
        );
    }

    // Kernel page fault handling must not take any locks, since the fault might have come
    // from a code path that holds that lock. Luckily, we only have to do one thing that
    // requires locking: looking up a PTE by its address. The only reason this requires
    // locking is because one of the page tables might get freed before it has been read
    // from. CPU-originating accesses don't suffer from this because the page tables
    // don't actually get freed until all CPUs that could possibly be accessing them
    // have received a shootdown IRQ. We can take advantage of this to alleviate the need
    // for locking entirely: as long as IRQs are disabled during the lookup, the page tables
    // involved can't possibly get freed.

    // Note that we don't save and restore IRQs. This is fine, since all code paths
    // result in either eventually returning through an interrupt path or panicking.

    disable_irq();

    if (!arch_pt_is_canonical(address)) {
        panic(
            "kernel code tried to %s non-canonical memory at 0x%Z (pc: 0x%Z, flags: %u)",
            type_to_string(type),
            address,
            pc,
            flags
        );
    }

    get_pte_result_t result = {};
    if (unlikely(!get_pte(&result, kernel_page_table, address))) {
        panic(
            "kernel code tried to %s unmapped memory at 0x%Z (pc: 0x%Z, flags: %u)",
            type_to_string(type),
            address,
            pc,
            flags
        );
    }

    pmap_t *cur_pmap = this_cpu_read_tl(pmap.current);
    unsigned level = arch_pt_levels() - 1;

    if (cur_pmap != NULL) {
        pte_t pte = arch_pt_read(cur_pmap->table, level, result.root_index);

        if (pte == 0) {
            // Despite not holding any locks here, this is completely free of race conditions:
            // - The value we're writing can't be stale, because non-zero PTEs in the top
            //   level kernel page table are permanent.
            // - The write cannot conflict with anything other CPUs are doing:
            //   The kernel part of user page tables is only ever written to during
            //   initialization and here. It can't be in the process of being initialized,
            //   because we're using it, so the only writes we have to worry about occur
            //   here. While it is certainly possible for other CPUs to be performing
            //   such a write at the same time as us, they will be writing the exact same
            //   value, because non-zero PTEs in the top level kernel page table are
            //   permanent.
            arch_pt_write(cur_pmap->table, level, result.root_index, result.root_pte);

            if (arch_pt_new_edge_needs_flush()) {
                arch_pt_flush_edge(address, kernel_page_table, -1, false, true);
            }

            return;
        }

        ASSERT(pte == result.root_pte);
    }

    if (is_access_allowed(result.level, result.pte, type)) {
        if (arch_pt_new_edge_needs_flush()) {
            arch_pt_flush_edge(address, kernel_page_table, -1, false, true);
        }

        arch_pt_flush_leaf(address, kernel_page_table, -1, false, true);
        return;
    }

    panic(
        "kernel code tried to %s memory that disallows such accesses at 0x%Z (pc: 0x%Z, flags: %u)",
        type_to_string(type),
        address,
        pc,
        flags
    );
}

unsigned vmm_to_pmap_flags(unsigned flags) {
    unsigned pmap_flags = 0;
    if (flags & HYDROGEN_MEM_READ) pmap_flags |= PMAP_READABLE;
    if (flags & HYDROGEN_MEM_WRITE) pmap_flags |= PMAP_WRITABLE;
    if (flags & HYDROGEN_MEM_EXEC) pmap_flags |= PMAP_EXECUTABLE;
    return pmap_flags;
}
