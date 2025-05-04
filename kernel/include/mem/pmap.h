#pragma once

#include "util/hlist.h"
#include "util/spinlock.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct cpu;

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

int pmap_create(pmap_t *out);
void pmap_switch(pmap_t *target); // must be called with preemption disabled, must not be called in irq context
void pmap_destroy(pmap_t *pmap);

// note: if pmap != NULL, the caller is responsible for locking
bool pmap_prepare(pmap_t *pmap, uintptr_t virt, size_t size);
void pmap_alloc(pmap_t *pmap, uintptr_t virt, size_t size, int flags); // you have to call pmem_reserve first
void pmap_move(pmap_t *smap, uintptr_t src, pmap_t *dmap, uintptr_t dest, size_t size); // undoes pmap_prepare
void pmap_unmap(pmap_t *pmap, uintptr_t virt, size_t size);                             // undoes pmap_prepare

void pmap_early_map(uintptr_t virt, uint64_t phys, size_t size, int flags);
void pmap_early_alloc(uintptr_t virt, size_t size, int flags);
