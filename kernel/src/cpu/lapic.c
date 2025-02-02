#include "cpu/lapic.h"
#include "asm/idle.h"
#include "asm/irq.h"
#include "asm/mmio.h"
#include "asm/msr.h"
#include "cpu/cpu.h"
#include "cpu/idt.h"
#include "cpu/irqvecs.h"
#include "cpu/xsave.h"
#include "drv/acpi.h"
#include "drv/pic.h"
#include "hydrogen/error.h"
#include "kernel/compiler.h"
#include "limine.h"
#include "mem/kvmm.h"
#include "mem/pmap.h"
#include "mem/vmalloc.h"
#include "sections.h"
#include "string.h"
#include "thread/sched.h"
#include "time/time.h"
#include "util/logging.h"
#include "util/object.h"
#include "util/panic.h"
#include "util/spinlock.h"
#include <stdint.h>

#define LAPIC_ID 0x20
#define LAPIC_EOI 0xb0
#define LAPIC_SPR 0xf0
#define LAPIC_ERR 0x280
#define LAPIC_ICR 0x300
#define LAPIC_LVT_TIMER 0x320
#define LAPIC_LVT_LINT0 0x350
#define LAPIC_LVT_LINT1 0x360
#define LAPIC_LVT_ERROR 0x370
#define LAPIC_TIMER_ICR 0x380
#define LAPIC_TIMER_CCR 0x390
#define LAPIC_TIMER_DCR 0x3e0

#define LAPIC_SPR_ENABLE 0x100

#define LAPIC_ICR_PENDING 0x1000
#define LAPIC_ICR_ASSERT 0x4000
#define LAPIC_ICR_LEVEL 0x8000

#define LAPIC_LVT_NMI 0x400
#define LAPIC_LVT_ACTIVE_LOW 0x2000
#define LAPIC_LVT_LEVEL 0x8000
#define LAPIC_LVT_MASKED 0x10000

#define LAPIC_TIMER_DCR_16 3

static void *xapic_regs;
static uint64_t msr_apic_base;
static spinlock_t pic_cpus_lock;

static uint32_t lapic_read32(unsigned reg) {
    if (cpu_features.x2apic) return rdmsr(0x800 + (reg >> 4));
    else return mmio_read32(xapic_regs, reg);
}

static void lapic_write32(unsigned reg, uint32_t value) {
    if (cpu_features.x2apic) wrmsr(0x800 + (reg >> 4), value);
    else mmio_write32(xapic_regs, reg, value);
}

static void lapic_write64(unsigned reg, uint64_t value) {
    if (cpu_features.x2apic) {
        wrmsr(0x800 + (reg >> 4), value);
    } else {
        mmio_write32(xapic_regs, reg + 0x10, value);
        mmio_write32(xapic_regs, reg, value);
    }
}

static void handle_lapic_error(UNUSED idt_frame_t *frame, UNUSED void *ctx) {
    lapic_write32(LAPIC_ERR, 0);
    uint32_t error = lapic_read32(LAPIC_ERR);
    panic("local apic error: 0x%x", error);
}

static void handle_spurious_irq(UNUSED idt_frame_t *frame, UNUSED void *ctx) {
    // Do nothing
}

void init_lapic_bsp(void) {
    if (!cpu_features.xapic) panic("xapic not available");

    msr_apic_base = rdmsr(MSR_APIC_BASE);

    if (cpu_features.x2apic) {
        msr_apic_base |= MSR_APIC_BASE_EXTD;
    } else {
        hydrogen_error_t error = map_phys_mem(
                &xapic_regs,
                msr_apic_base & (cpu_features.paddr_mask & ~0xfff),
                0x1000,
                PMAP_WRITE,
                CACHE_NONE
        );
        if (unlikely(error)) panic("failed to map xapic registers (%d)", error);
    }

    idt_install(VEC_IRQ_APIC_ERR, handle_lapic_error, NULL);
    idt_install(VEC_IRQ_SPURIOUS, handle_spurious_irq, NULL);
}

void init_lapic(void) {
    wrmsr(MSR_APIC_BASE, msr_apic_base);

    lapic_write32(LAPIC_ERR, 0);
    lapic_write32(LAPIC_SPR, VEC_IRQ_SPURIOUS); // disable lapic during init
    lapic_write32(LAPIC_LVT_TIMER, VEC_IRQ_TIMER | LAPIC_LVT_MASKED);
    lapic_write32(LAPIC_LVT_LINT0, VEC_IRQ_SPURIOUS | LAPIC_LVT_MASKED);
    lapic_write32(LAPIC_LVT_LINT1, VEC_IRQ_SPURIOUS | LAPIC_LVT_MASKED);
    lapic_write32(LAPIC_LVT_ERROR, VEC_IRQ_APIC_ERR);
    lapic_write32(LAPIC_TIMER_DCR, LAPIC_TIMER_DCR_16);
    lapic_write32(LAPIC_TIMER_ICR, 0);
    lapic_write32(LAPIC_SPR, VEC_IRQ_SPURIOUS | LAPIC_SPR_ENABLE);

    lapic_write32(LAPIC_ERR, 0);
    uint32_t error = lapic_read32(LAPIC_ERR);
    if (error) panic("error during local apic initialization (0x%x)", error);

    current_cpu.apic_id = lapic_read32(LAPIC_ID);
    if (!cpu_features.x2apic) current_cpu.apic_id >>= 24;

    if (current_cpu.apic_id < 256) {
        irq_state_t state = spin_lock(&pic_cpus_lock);
        current_cpu.pic_next = pic_cpus;
        pic_cpus = current_cpu_ptr;
        spin_unlock(&pic_cpus_lock, state);
    }

    const acpi_madt_t *madt = (const acpi_madt_t *)get_acpi_table("APIC");
    if (unlikely(!madt)) panic("madt table not found");

    uint32_t acpi_id = UINT32_MAX;

    ACPI_MADT_FOREACH(madt, entry) {
        if (entry->type == ACPI_MADT_XAPIC && entry->xapic.apic_id == current_cpu.apic_id) {
            acpi_id = entry->xapic.acpi_id;
            break;
        } else if (entry->type == ACPI_MADT_X2APIC && entry->x2apic.apic_id == current_cpu.apic_id) {
            acpi_id = entry->x2apic.acpi_id;
            break;
        }
    }

    if (acpi_id == UINT32_MAX) panic("failed to find acpi id for processor");

    ACPI_MADT_FOREACH(madt, entry) {
        uint32_t cpu;
        uint16_t flags;
        uint8_t input;

        if (entry->type == ACPI_MADT_XAPIC_NMI) {
            cpu = entry->xapic_nmi.acpi_id;
            flags = entry->xapic_nmi.flags;
            input = entry->xapic_nmi.input;
            if (cpu == 0xff) cpu = UINT32_MAX;
        } else if (entry->type == ACPI_MADT_X2APIC_NMI) {
            cpu = entry->x2apic_nmi.acpi_id;
            flags = entry->x2apic_nmi.flags;
            input = entry->x2apic_nmi.input;
        } else {
            continue;
        }

        if (cpu == UINT32_MAX || cpu == acpi_id) {
            uint32_t entry = LAPIC_LVT_NMI;

            if ((flags & ACPI_MADT_ISO_POLARITY_MASK) == ACPI_MADT_ISO_ACTIVE_LOW) entry |= LAPIC_LVT_ACTIVE_LOW;
            if ((flags & ACPI_MADT_ISO_TRIGGER_MASK) == ACPI_MADT_ISO_TRIGGER_LEVEL) entry |= LAPIC_LVT_LEVEL;

            lapic_write32(input ? LAPIC_LVT_LINT1 : LAPIC_LVT_LINT0, entry);
        }
    }
}

void lapic_arm_timer(lapic_timer_mode_t mode, bool interrupts) {
    uint32_t entry = (mode << 17) | VEC_IRQ_TIMER;
    if (!interrupts) entry |= LAPIC_LVT_MASKED;
    lapic_write32(LAPIC_LVT_TIMER, entry);
}

void lapic_start_timer(uint32_t ticks) {
    lapic_write32(LAPIC_TIMER_ICR, ticks);
}

uint32_t lapic_read_timer(void) {
    return lapic_read32(LAPIC_TIMER_CCR);
}

void lapic_eoi(void) {
    lapic_write32(LAPIC_EOI, 0);
}

void send_ipi(int vector, cpu_t *dest) {
    if (!dest) {
        for (cpu_t *cpu = cpus; cpu != NULL; cpu = cpu->next) {
            if (cpu != current_cpu_ptr) send_ipi(vector, cpu);
        }

        return;
    }

    uint64_t icr = LAPIC_ICR_ASSERT | vector;

    if (cpu_features.x2apic) {
        icr |= (uint64_t)dest->apic_id << 32;
        lapic_write64(LAPIC_ICR, icr);
    } else {
        icr |= (uint64_t)dest->apic_id << 56;

        irq_state_t state = save_disable_irq();
        lapic_write64(LAPIC_ICR, icr);
        while (lapic_read32(LAPIC_ICR) & LAPIC_ICR_PENDING) cpu_relax();
        restore_irq(state);
    }
}

/*
 * SMP initialization occurs in five phases:
 * 1. The kernel init thread creates and starts the CPU init threads, then goes to sleep.
 * 2. The CPU init threads create the CPU init data and signal the target CPUs to start the kernel, then goes to sleep.
 * 3. The target CPUs do all the initialization needed for the scheduler to function, and wake up their CPU init thread.
 * 4. The CPU init threads migrate themselves onto the target CPUs, and finish initialization.
 * 5. The last CPU init thread to finish completion wakes up the kernel init thread.
 */

typedef struct {
    void *idle_stack;
    cpu_t cpu;
    spinlock_t init_lock;
    thread_t *init_thread;
} cpu_init_data_t;

static size_t smp_done;
static thread_t *smp_init_thread;
static spinlock_t smp_init_lock;

_Noreturn void smp_init_cpu(cpu_init_data_t *data) {
    static size_t smp_started;
    data->cpu.id = __atomic_fetch_add(&smp_started, 1, __ATOMIC_RELAXED) + 1;

    init_cpu(&data->cpu);
    init_lapic();
    init_time_local();
    init_sched_early();
    init_xsave();

    __atomic_fetch_add(&num_cpus, 1, __ATOMIC_SEQ_CST);

    irq_state_t state = spin_lock(&data->init_lock);
    sched_wake(data->init_thread);
    spin_unlock(&data->init_lock, state);

    sched_idle();
}

extern _Noreturn void smp_cpu_thunk(struct limine_mp_info *);

static void ap_init_thread_func(void *ptr) {
    struct limine_mp_info *info = ptr;

    cpu_init_data_t *data = vmalloc(sizeof(*data));
    if (unlikely(!data)) panic("failed to allocate cpu init data");
    memset(data, 0, sizeof(*data));

    data->init_thread = current_thread;

    data->idle_stack = alloc_kernel_stack();
    if (unlikely(!data->idle_stack)) panic("failed to allocate cpu idle stack");

    void *exc_stack = alloc_kernel_stack();
    if (unlikely(!exc_stack)) panic("failed to allocate cpu exception stack");
    data->cpu.tss.ist[0] = (uintptr_t)exc_stack;

    data->cpu.sched.idle.xsave = xsave_alloc();
    if (unlikely(!data->cpu.sched.idle.xsave)) panic("failed to allocate idle xsave area");

    info->extra_argument = (uintptr_t)data;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);

    irq_state_t state = spin_lock(&data->init_lock);
    info->goto_address = smp_cpu_thunk;
    sched_wait(0, &data->init_lock);
    spin_unlock(&data->init_lock, state);

    sched_migrate(&data->cpu);
    init_sched_late();

    if (__atomic_fetch_sub(&smp_done, 1, __ATOMIC_SEQ_CST) == 1) {
        irq_state_t state = spin_lock(&data->init_lock);
        if (smp_init_thread) sched_wake(smp_init_thread);
        spin_unlock(&data->init_lock, state);
    }
}

void init_smp(void) {
    static LIMINE_REQ struct limine_mp_request mp_req = {.id = LIMINE_MP_REQUEST, .flags = LIMINE_MP_X2APIC};
    if (!mp_req.response) return;

    smp_done = mp_req.response->cpu_count - 1;
    smp_init_thread = current_thread;

    for (uint64_t i = 0; i < mp_req.response->cpu_count; i++) {
        struct limine_mp_info *info = mp_req.response->cpus[i];
        if (info->lapic_id == mp_req.response->bsp_lapic_id) continue;

        // These threads have to be created on the current CPU to avoid a race condition in `sched_create`'s CPU
        // selection code.
        thread_t *thread;
        hydrogen_error_t error = sched_create(&thread, ap_init_thread_func, info, current_cpu_ptr);
        if (unlikely(error)) panic("failed to create cpu initialization thread (%d)", error);
        sched_wake(thread);
        obj_deref(&thread->base);
    }

    irq_state_t state = spin_lock(&smp_init_lock);

    if (__atomic_load_n(&smp_done, __ATOMIC_SEQ_CST) != 0) {
        sched_wait(0, &smp_init_lock);
        smp_init_thread = NULL;
    }

    spin_unlock(&smp_init_lock, state);

    printk("smp: %U cpus online\n", num_cpus);
}
