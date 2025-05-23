#include "x86_64/lapic.h"
#include "arch/idle.h"
#include "arch/irq.h"
#include "arch/mmio.h"
#include "arch/pmap.h"
#include "cpu/cpudata.h"
#include "drv/acpi/acpi.h" /* IWYU pragma: keep */
#include "init/task.h"
#include "kernel/compiler.h"
#include "mem/kvmm.h"
#include "proc/sched.h"
#include "uacpi/acpi.h"
#include "uacpi/status.h"
#include "uacpi/tables.h"
#include "util/hlist.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/printk.h"
#include "util/spinlock.h"
#include "x86_64/cpu.h"
#include "x86_64/idtvec.h"
#include "x86_64/msr.h"
#include <stdint.h>

#define LAPIC_ID 0x20
#define LAPIC_EOI 0xb0
#define LAPIC_SVR 0xf0
#define LAPIC_ERR 0x280
#define LAPIC_ICR 0x300
#define LAPIC_LVT_TIMER 0x320
#define LAPIC_LVT_LINT0 0x350
#define LAPIC_LVT_LINT1 0x360
#define LAPIC_LVT_ERROR 0x370
#define LAPIC_TIMER_ICR 0x380
#define LAPIC_TIMER_CCR 0x390
#define LAPIC_TIMER_DCR 0x3e0

#define LAPIC_SVR_ENABLE (1u << 8)

#define LAPIC_ICR_PENDING (1u << 12)
#define LAPIC_ICR_LEVEL (1u << 14)

#define LAPIC_LVT_NMI (4u << 8)
#define LAPIC_LVT_ACTIVE_LOW (1u << 13)
#define LAPIC_LVT_LEVEL_TRIGGERED (1u << 15)
#define LAPIC_LVT_MASKED (1u << 16)

#define LAPIC_TIMER_DCR_1 0xb

static uintptr_t lapic_regs;
static uint64_t lapic_regs_phys;
static bool have_lapic;

static void setup_reg_access(void) {
    if (x86_64_cpu_features.x2apic) return;

    lapic_regs_phys = (x86_64_rdmsr(X86_64_MSR_APIC_BASE) & ~0xfff) & x86_64_cpu_features.paddr_mask;
    int error = map_mmio(&lapic_regs, lapic_regs_phys, 0x1000, PMAP_READABLE | PMAP_WRITABLE | PMAP_CACHE_UC);
    if (unlikely(error)) panic("lapic: failed to map registers (%e)", error);
}

static void setup_reg_access_local(void) {
    uint64_t msr = x86_64_rdmsr(X86_64_MSR_APIC_BASE);
    uint64_t nmsr = msr | X86_64_MSR_APIC_BASE_ENABLE;

    if (x86_64_cpu_features.x2apic) {
        nmsr |= X86_64_MSR_APIC_BASE_EXTD;
    } else {
        nmsr &= ~(x86_64_cpu_features.paddr_mask & ~0xfff);
        nmsr |= lapic_regs_phys;
    }

    if (msr != nmsr) x86_64_wrmsr(X86_64_MSR_APIC_BASE, nmsr);
}

static inline uint32_t lapic_read(unsigned reg) {
    if (x86_64_cpu_features.x2apic) return x86_64_rdmsr(0x800 + (reg >> 4));
    else return mmio_read32(lapic_regs, reg);
}

static inline void lapic_write(unsigned reg, uint32_t value) {
    if (x86_64_cpu_features.x2apic) x86_64_wrmsr(0x800 + (reg >> 4), value);
    else mmio_write32(lapic_regs, reg, value);
}

static inline void lapic_write64(unsigned reg, uint64_t value) {
    if (x86_64_cpu_features.x2apic) {
        x86_64_wrmsr(0x800 + (reg >> 4), value);
    } else {
        mmio_write32(lapic_regs, reg + 0x10, value >> 32);
        mmio_write32(lapic_regs, reg, value);
    }
}

static inline void lapic_fence(void) {
    if (x86_64_cpu_features.x2apic) {
        // in x2apic mode the register writes aren't serializing, so without this the other cpu
        // might get the interrupt before it sees data that the interrupt handler uses
        asm("mfence; lfence" ::: "memory");
    } else {
        // in xapic mode a compiler barrier is enough
        asm("" ::: "memory");
    }
}

static void x86_64_lapic_init(void) {
    if (!x86_64_cpu_features.apic) panic("cpu does not have an integrated local apic");
    setup_reg_access();

    uacpi_table madt_table;
    uacpi_status status = uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &madt_table);
    if (uacpi_unlikely_error(status)) panic("lapic: failed to find madt table: %s", uacpi_status_to_string(status));
    x86_64_lapic_init_local(madt_table.ptr);
    uacpi_table_unref(&madt_table);
}

INIT_DEFINE_EARLY(x86_64_lapic, x86_64_lapic_init, INIT_REFERENCE(memory), INIT_REFERENCE(acpi_tables));

static void setup_lint_nmi(uint8_t lint, uint16_t flags) {
    if (lint >= 2) {
        printk("lapic: firmware requested local nmi on non-existed input lint%u\n", lint);
        return;
    }

    uint32_t lvt = LAPIC_LVT_NMI;

    if ((flags & ACPI_MADT_POLARITY_MASK) == ACPI_MADT_POLARITY_ACTIVE_LOW) {
        lvt |= LAPIC_LVT_ACTIVE_LOW;
    }

    if ((flags & ACPI_MADT_TRIGGERING_MASK) == ACPI_MADT_TRIGGERING_LEVEL) {
        printk("lapic: firmware requested level-triggered local nmi, but nmis are always edge triggered\n");
    }

    lapic_write(lint ? LAPIC_LVT_LINT1 : LAPIC_LVT_LINT0, lvt);
}

void x86_64_lapic_init_local(struct acpi_madt *madt) {
    setup_reg_access_local();
    lapic_write(LAPIC_SVR, X86_64_IDT_LAPIC_SPURIOUS); // disable local apic during init
    lapic_write(LAPIC_ERR, 0);                         // clear stale errors

    uint32_t id = lapic_read(LAPIC_ID);
    if (!x86_64_cpu_features.x2apic) id >>= 24;

    if (get_current_cpu() == &boot_cpu) {
        if (id > 0xff) panic("lapic: boot cpu is not addressable by i/o apics");

        this_cpu_write(arch.apic_id, id);

        struct acpi_entry_hdr *cur = madt->entries;
        struct acpi_entry_hdr *end = (void *)madt + madt->hdr.length;

        while (cur < end) {
            if (cur->type == ACPI_MADT_ENTRY_TYPE_LAPIC) {
                struct acpi_madt_lapic *entry = (void *)cur;

                if (entry->id == id) {
                    this_cpu_write(arch.acpi_id, entry->uid);
                    break;
                }
            } else if (cur->type == ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC) {
                struct acpi_madt_x2apic *entry = (void *)cur;

                if (entry->id == id) {
                    this_cpu_write(arch.acpi_id, entry->uid);
                    break;
                }
            }

            cur = (void *)cur + cur->length;
        }

        if (cur >= end) panic("failed to find acpi id for boot cpu");
    } else {
        ENSURE(id == this_cpu_read(arch.apic_id));
    }

    lapic_write(LAPIC_LVT_TIMER, LAPIC_LVT_MASKED | X86_64_IDT_LAPIC_TIMER);
    lapic_write(LAPIC_LVT_LINT0, LAPIC_LVT_MASKED | X86_64_IDT_LAPIC_SPURIOUS);
    lapic_write(LAPIC_LVT_LINT1, LAPIC_LVT_MASKED | X86_64_IDT_LAPIC_SPURIOUS);
    lapic_write(LAPIC_LVT_ERROR, X86_64_IDT_LAPIC_ERROR);

    lapic_write(LAPIC_TIMER_DCR, LAPIC_TIMER_DCR_1);
    lapic_write(LAPIC_SVR, LAPIC_SVR_ENABLE | X86_64_IDT_LAPIC_SPURIOUS);

    lapic_write(LAPIC_ERR, 0);
    uint32_t error = lapic_read(LAPIC_ERR);
    if (error) panic("lapic: got error 0x%x during initialization\n", error);

    have_lapic = true;

    struct acpi_entry_hdr *cur = madt->entries;
    struct acpi_entry_hdr *end = (void *)madt + madt->hdr.length;

    uint32_t self_id = this_cpu_read(arch.acpi_id);

    while (cur < end) {
        if (cur->type == ACPI_MADT_ENTRY_TYPE_LAPIC_NMI) {
            struct acpi_madt_lapic_nmi *entry = (void *)cur;

            if (entry->uid == 0xff || entry->uid == self_id) {
                setup_lint_nmi(entry->lint, entry->flags);
            }
        } else if (cur->type == ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC_NMI) {
            struct acpi_madt_x2apic_nmi *entry = (void *)cur;

            if (entry->uid == 0xffffffff || entry->uid == self_id) {
                setup_lint_nmi(entry->lint, entry->flags);
            }
        }

        cur = (void *)cur + cur->length;
    }
}

void x86_64_lapic_eoi(void) {
    lapic_write(LAPIC_EOI, 0);
}

void x86_64_lapic_ipi(uint32_t target_id, uint8_t vector, uint32_t flags) {
    if (!have_lapic) return;

    uint64_t icr = vector | flags;

    if ((flags & X86_64_LAPIC_IPI_INIT_DEASSERT) != X86_64_LAPIC_IPI_INIT_DEASSERT) {
        icr |= LAPIC_ICR_LEVEL;
    }

    if (x86_64_cpu_features.x2apic) {
        icr |= (uint64_t)target_id << 32;
    } else {
        icr |= (uint64_t)target_id << 56;
    }

    lapic_fence();
    lapic_write64(LAPIC_ICR, icr);

    if (!x86_64_cpu_features.x2apic) {
        while ((lapic_read(LAPIC_ICR) & LAPIC_ICR_PENDING) != 0) {
            cpu_relax();
        }
    }
}

void x86_64_lapic_timer_setup(x86_64_lapic_timer_mode_t mode, bool interrupt) {
    x86_64_lapic_timer_stop();

    uint32_t lvt = mode | X86_64_IDT_LAPIC_TIMER;
    if (!interrupt) lvt |= LAPIC_LVT_MASKED;
    lapic_write(LAPIC_LVT_TIMER, lvt);
}

void x86_64_lapic_timer_start(uint32_t count) {
    lapic_write(LAPIC_TIMER_ICR, count);
}

uint32_t x86_64_lapic_timer_remaining(void) {
    return lapic_read(LAPIC_TIMER_CCR);
}

void x86_64_lapic_irq_error(void) {
    lapic_write(LAPIC_ERR, 0);
    printk("lapic: got error 0x%x\n", lapic_read(LAPIC_ERR));
    x86_64_lapic_eoi();
}

void x86_64_lapic_irq_spurious(void) {
}

typedef struct {
    hlist_t handlers;
} irq_data_t;

#define NUM_IRQS (X86_64_IDT_IRQ_MAX - X86_64_IDT_IRQ_MIN + 1)

static irq_data_t irqs[NUM_IRQS];
static uint64_t irq_map[(NUM_IRQS + 63) / 64];
static spinlock_t irqs_lock;

void x86_64_lapic_irq_handle(uint8_t vector) {
    preempt_state_t pstate = preempt_lock();

    irq_state_t state = spin_acq(&irqs_lock);
    irq_data_t *data = &irqs[vector - X86_64_IDT_IRQ_MIN];

    LIST_FOREACH(data->handlers, irq_handler_t, node, handler) {
        if (handler->func(handler->ctx)) goto done;
    }

    printk("lapic: unhandled irq %u on cpu %z\n", vector, this_cpu_read(id));

done:
    spin_rel(&irqs_lock, state);
    x86_64_lapic_eoi();
    preempt_unlock(pstate);
}

int arch_irq_allocate(irq_t *out) {
    irq_state_t state = spin_acq(&irqs_lock);
    uint64_t *map = irq_map;

    for (size_t index = 0; index < NUM_IRQS; index += 64) {
        uint64_t value = *map++;
        if (value == UINT64_MAX) continue;

        size_t offset = __builtin_ctzll(~value);
        size_t irq_idx = offset + index;
        if (irq_idx >= NUM_IRQS) break;

        map[-1] |= 1ull << offset;
        spin_rel(&irqs_lock, state);
        out->vector = X86_64_IDT_IRQ_MIN + irq_idx;
        return 0;
    }

    spin_rel(&irqs_lock, state);
    return EBUSY;
}

void arch_irq_add_handler(irq_t *irq, irq_handler_t *handler) {
    irq_state_t state = spin_acq(&irqs_lock);
    hlist_insert_head(&irqs[irq->vector - X86_64_IDT_IRQ_MIN].handlers, &handler->node);
    spin_rel(&irqs_lock, state);
}

void arch_irq_remove_handler(irq_t *irq, irq_handler_t *handler) {
    irq_state_t state = spin_acq(&irqs_lock);
    hlist_remove(&irqs[irq->vector - X86_64_IDT_IRQ_MIN].handlers, &handler->node);
    spin_rel(&irqs_lock, state);
}

void arch_irq_free(const irq_t *irq) {
    size_t index = irq->vector - X86_64_IDT_IRQ_MIN;
    irq_state_t state = spin_acq(&irqs_lock);

    ASSERT(hlist_empty(&irqs[index].handlers));
    irq_map[index / 64] &= ~(1ull << (index % 64));

    spin_rel(&irqs_lock, state);
}
