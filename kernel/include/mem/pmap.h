#pragma once

#include "arch/context.h"
#include "util/hlist.h"
#include "util/spinlock.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct cpu;
struct page;
struct vmm;

typedef struct {
    void *table;
    hlist_t cpus;
    int asid;
    spinlock_t cpus_lock;
} pmap_t;

typedef struct {
    struct cpu *cpu;
    void *table;
    hlist_node_t node;
} pmap_asid_data_t;

typedef struct {
    pmap_asid_data_t *asids;
    pmap_t *current;
} pmap_cpu_data_t;

void pmap_init(void);
void pmap_init_switch(void);
void pmap_init_cpu(struct cpu *cpu);

int pmap_create(struct vmm *vmm);
void pmap_switch(pmap_t *target); // must be called with preemption disabled, must not be called in irq context

void pmap_prepare_destroy(pmap_t *pmap);
void pmap_destroy_range(struct vmm *vmm, uintptr_t virt, size_t size);
void pmap_finish_destruction(struct vmm *vmm);

// note: if vmm != NULL, the caller is responsible for locking
bool pmap_prepare(struct vmm *vmm, uintptr_t virt, size_t size);
void pmap_alloc(struct vmm *vmm, uintptr_t virt, size_t size, int flags); // you have to call pmem_reserve first
void pmap_map(struct vmm *vmm, uintptr_t virt, uint64_t phys, size_t size, int flags);
void pmap_remap(struct vmm *vmm, uintptr_t virt, size_t size, int flags);
void pmap_clone(struct vmm *vmm, struct vmm *dest, uintptr_t virt, size_t size, bool cow);
void pmap_move(struct vmm *svmm, uintptr_t src, struct vmm *dvmm, uintptr_t dest, size_t size); // undoes pmap_prepare
void pmap_unmap(struct vmm *vmm, uintptr_t virt, size_t size);                                  // undoes pmap_prepare
struct page *pmap_get_mapping(struct vmm *vmm, uintptr_t virt);

void pmap_early_map(uintptr_t virt, uint64_t phys, size_t size, int flags);
void pmap_early_alloc(uintptr_t virt, size_t size, int flags);
void pmap_early_cleanup(void);

typedef enum {
    PMAP_FAULT_READ,
    PMAP_FAULT_WRITE,
    PMAP_FAULT_EXECUTE,
} pmap_fault_type_t;

#define PMAP_FAULT_USER (1u << 0)

// NOTE: This might disable IRQs!
void pmap_handle_page_fault(
        arch_context_t *context,
        uintptr_t pc,
        uintptr_t address,
        pmap_fault_type_t type,
        unsigned flags
);

unsigned vmm_to_pmap_flags(unsigned flags);
