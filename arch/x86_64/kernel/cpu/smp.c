#include "smp.h"
#include "arch/idle.h"
#include "arch/pmap.h"
#include "arch/stack.h"
#include "arch/time.h"
#include "cpu/cpudata.h"
#include "cpu/cpumask.h"
#include "init/main.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "mem/kvmm.h"
#include "mem/memmap.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/vmalloc.h"
#include "proc/event.h"
#include "proc/sched.h"
#include "string.h"
#include "uacpi/acpi.h"
#include "uacpi/status.h"
#include "uacpi/tables.h"
#include "util/printk.h"
#include "util/slist.h"
#include "util/time.h"
#include "x86_64/cpu.h"
#include "x86_64/cpuid.h"
#include "x86_64/cr.h"
#include "x86_64/lapic.h"
#include "x86_64/msr.h"
#include "x86_64/tss.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static int alloc_cpu(cpu_t **out) {
    cpu_t *cpu = vmalloc(sizeof(*cpu));
    if (unlikely(!cpu)) return ENOMEM;
    memset(cpu, 0, sizeof(*cpu));

    int error = pmap_init_cpu(cpu);
    if (unlikely(error)) {
        vfree(cpu, sizeof(*cpu));
        return error;
    }

    for (int i = 0; i < X86_64_IST_MAX; i++) {
        void *stack = alloc_kernel_stack();

        if (unlikely(!stack)) {
            for (int j = 0; j < i; j++) {
                free_kernel_stack((void *)(cpu->arch.tss.ist[j] - KERNEL_STACK_SIZE));
            }

            vfree(cpu, sizeof(*cpu));
            return ENOMEM;
        }

        cpu->arch.tss.ist[i] = (uintptr_t)stack + KERNEL_STACK_SIZE;
    }

    *out = cpu;
    return 0;
}

static void free_cpu(cpu_t *cpu) {
    for (int i = 0; i < X86_64_IST_MAX; i++) {
        free_kernel_stack((void *)(cpu->arch.tss.ist[i] - KERNEL_STACK_SIZE));
    }

    pmap_free_cpu(cpu);
    vfree(cpu, sizeof(*cpu));
}

typedef struct {
    unsigned char reserved[8];
    uint32_t cr4;
    uint32_t cr3;
    cpu_t *cpu;
    void *ctx;
    uintptr_t hhdm;
    uintptr_t rsp;
    uint64_t efer;
    uint64_t final_cr3;
    uint32_t cr0;
    struct {
        uint32_t eip;
        uint32_t cs;
    } __attribute__((packed)) jmp_target;
    struct {
        uint32_t eip;
        uint32_t cs;
    } __attribute__((packed)) jmp_target_wakeup;
    uint16_t flags;
    uint16_t mtrr_count;
    uint64_t mtrr_default;
    uint64_t mtrr_fixed[SMP_MTRR_NUM_FIXED];
    uint64_t mtrr_variable[SMP_MTRR_VAR_MAX][2];
    uint64_t pat;
    uint32_t mtrr_fixed_msrs[SMP_MTRR_NUM_FIXED];
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) temp_gdt_desc;
} mp_data_t;

extern const void x86_64_smp_trampoline, x86_64_smp_trampoline_wakeup_entry, x86_64_smp_trampoline_end;

static void free_mapping(void *table, uintptr_t virt) {
    for (unsigned level = arch_pt_levels() - 1; level > 0; level--) {
        pte_t pte = arch_pt_read(table, level, arch_pt_get_index(virt, level));
        pmem_free_now(virt_to_page(table));
        if (pte == 0) return;
        table = arch_pt_edge_target(level, pte);
    }
}

static void free_temp_page_tables(uint32_t cr3, uint64_t phys) {
    void *table = phys_to_virt(cr3);

    free_mapping(table, phys);
    free_mapping(table, (uintptr_t)&x86_64_smp_trampoline);

    pmem_free_now(virt_to_page(table));
}

static bool add_mapping(void *table, uintptr_t virt, uint64_t phys, int flags) {
    for (unsigned level = arch_pt_levels() - 1; level > 0; level--) {
        page_t *page = pmem_alloc_now();
        if (unlikely(!page)) return false;

        void *child = page_to_virt(page);
        memset(child, 0, PAGE_SIZE);
        arch_pt_write(table, level, arch_pt_get_index(virt, level), arch_pt_create_edge(level, child));
        table = child;
    }

    arch_pt_write(table, 0, arch_pt_get_index(virt, 0), arch_pt_create_leaf(0, phys, flags));
    return true;
}

static bool create_temp_page_tables(mp_data_t *data, uint64_t phys) {
    page_t *page = pmem_alloc_slow_and_unreliable_now(0, UINT32_MAX, 0x1000, 1);
    if (unlikely(!page)) return false;

    void *table = page_to_virt(page);
    memset(table, 0, PAGE_SIZE);

    if (!add_mapping(table, phys, phys, PMAP_READABLE | PMAP_EXECUTABLE)) goto err;

    if (!add_mapping(
                table,
                (uintptr_t)&x86_64_smp_trampoline,
                sym_to_phys(&x86_64_smp_trampoline),
                PMAP_READABLE | PMAP_EXECUTABLE
        )) {
        goto err;
    }

    data->cr3 = page_to_phys(page);
    return true;
err:
    free_temp_page_tables(page_to_phys(page), phys);
    return false;
}

static int save_mtrr(mp_data_t *data) {
    if (x86_64_cpu_features.cpuid_low < 1) return 0;

    unsigned eax, ebx, ecx, edx;
    cpuid(1, &eax, &ebx, &ecx, &edx);
    if ((edx & (1u << 12)) == 0) return 0;

    uint64_t capabilities = x86_64_rdmsr(X86_64_MSR_MTRR_CAP);
    data->mtrr_count = capabilities & 0xff;

    if (data->mtrr_count > SMP_MTRR_VAR_MAX) {
        printk("smp: too many mtrr ranges (got %u, support %u)\n", data->mtrr_count, SMP_MTRR_VAR_MAX);
        return EINVAL;
    }

    if ((capabilities & (1u << 8)) != 0) {
        data->flags |= SMP_MTRR_FIXED;

        for (int i = 0; i < SMP_MTRR_NUM_FIXED; i++) {
            data->mtrr_fixed[i] = x86_64_rdmsr(data->mtrr_fixed_msrs[i]);
        }
    }

    data->mtrr_default = x86_64_rdmsr(X86_64_MSR_MTRR_DEF_TYPE);

    for (size_t i = 0; i < data->mtrr_count; i++) {
        data->mtrr_variable[i][0] = x86_64_rdmsr(X86_64_MSR_MTRR_PHYS_BASE(i));
        data->mtrr_variable[i][1] = x86_64_rdmsr(X86_64_MSR_MTRR_PHYS_MASK(i));
    }

    data->flags |= SMP_MTRR_SAVED;
    return 0;
}

static void save_pat(mp_data_t *data) {
    if (!x86_64_cpu_features.pat) return;

    data->pat = x86_64_rdmsr(X86_64_MSR_PAT);
    data->flags |= SMP_PAT_SAVED;
}

static int init_mp_data(mp_data_t *data, uint64_t phys) {
    size_t size = &x86_64_smp_trampoline_end - &x86_64_smp_trampoline;
    ASSERT(size <= SMP_MAX_TRAMPOLINE_SIZE);
    memcpy(data, &x86_64_smp_trampoline, size);

    int error = save_mtrr(data);
    if (unlikely(error)) return error;

    save_pat(data);

    data->cr4 = x86_64_read_cr4();
    if (unlikely(!create_temp_page_tables(data, phys))) return ENOMEM;
    data->hhdm = hhdm_base;
    data->efer = x86_64_rdmsr(X86_64_MSR_EFER) & ~X86_64_MSR_EFER_LMA;
    data->cr0 = x86_64_read_cr0();
    data->final_cr3 = x86_64_read_cr3();

    if (x86_64_cpu_features.pcid) data->cr4 &= ~X86_64_CR4_PCIDE;
    if (x86_64_cpu_features.mce) data->cr4 &= ~X86_64_CR4_MCE;
    if (x86_64_cpu_features.pge) data->cr4 &= ~X86_64_CR4_PGE;

    data->jmp_target.eip += phys;
    data->jmp_target_wakeup.eip += phys;
    data->temp_gdt_desc.base += phys;

    return 0;
}

static int init_mp_data_for_cpu(mp_data_t *data, cpu_t *cpu, void *init_ctx) {
    data->cpu = cpu;
    data->ctx = init_ctx;

    if (data->rsp == 0) {
        void *stack = alloc_kernel_stack();
        if (unlikely(!stack)) return ENOMEM;
        data->rsp = (uintptr_t)stack + KERNEL_STACK_SIZE;
    }

    return 0;
}

static int mp_data_wait(mp_data_t *data, uint64_t responsive_timeout) {
    uint64_t start = arch_read_time();

    while (__atomic_load_n(&data->rsp, __ATOMIC_ACQUIRE) != 0) {
        if (arch_read_time() - start >= responsive_timeout) return ETIMEDOUT;
        cpu_relax();
    }

    return 0;
}

static void cleanup_mp_data(mp_data_t *data, uint64_t phys) {
    if (data->rsp != 0) {
        free_kernel_stack((void *)(data->rsp - KERNEL_STACK_SIZE));
    }

    free_temp_page_tables(data->cr3, phys);
}

typedef struct {
    mp_data_t *data;
} sipi_ctx_t;

static int try_sipi_wakeup(cpu_t *cpu, sipi_ctx_t *ctx) {
    x86_64_lapic_ipi(cpu->arch.apic_id, 0, X86_64_LAPIC_IPI_INIT);
    sched_prepare_wait(false);
    sched_perform_wait(10 * NS_PER_MS);

    for (int i = 0; i < 2; i++) {
        x86_64_lapic_ipi(cpu->arch.apic_id, virt_to_phys(ctx->data) >> 12, X86_64_LAPIC_IPI_STARTUP);
        time_stall(200 * NS_PER_US);
    }

    int error = mp_data_wait(ctx->data, 10 * NS_PER_MS);
    if (unlikely(error)) return error;

    return 0;
}

typedef int (*launch_func_t)(cpu_t *, void *, void *);

static int launch_func_sipi(cpu_t *cpu, void *init_ctx, void *ptr) {
    sipi_ctx_t *ctx = ptr;
    mp_data_t *data = ctx->data;

    if (data == NULL) {
        page_t *page = pmem_alloc_slow_and_unreliable_now(0, 0xfffff, 0x1000, 1);
        if (unlikely(!page)) return ENOMEM;

        data = page_to_virt(page);
        int error = init_mp_data(data, page_to_phys(page));
        if (unlikely(error)) {
            pmem_free_now(page);
            return error;
        }
        ctx->data = data;
    }

    int error = init_mp_data_for_cpu(data, cpu, init_ctx);
    if (unlikely(error)) return error;

    for (int i = 0; i < 10; i++) {
        if (i != 0) printk("smp: timed out while initializing cpu, retrying\n");
        int error = try_sipi_wakeup(cpu, ctx);
        if (likely(error == 0)) return 0;
        if (unlikely(error != ETIMEDOUT)) return error;
    }

    return ETIMEDOUT;
}

static void sipi_cleanup(void *ptr) {
    sipi_ctx_t *ctx = ptr;

    if (ctx->data != NULL) {
        cleanup_mp_data(ctx->data, virt_to_phys(ctx->data));
        pmem_free_now(virt_to_page(ctx->data));
    }

    vfree(ctx, sizeof(*ctx));
}

typedef struct {
    uint16_t command;
    uint16_t reserved;
    uint32_t apic_id;
    uint64_t wakeup_vector;
    unsigned char os_reserved[2032];
    unsigned char fw_reserved[2048];
} mp_wakeup_mailbox_t;

_Static_assert(sizeof(mp_wakeup_mailbox_t) == 4096, "Wrong size for mp_wakeup_mailbox_ctx_t");

#define MP_WAKEUP_NOOP 0
#define MP_WAKEUP_JUMP 1

struct mp_wakeup_ctx {
    mp_wakeup_mailbox_t *mailbox;
    mp_data_t *data;
    uint64_t phys;
    uint32_t version;
};

static bool wakeup_wait_for_command(mp_wakeup_mailbox_t *mailbox, uint64_t timeout) {
    uint64_t start = arch_read_time();

    while (__atomic_load_n(&mailbox->command, __ATOMIC_ACQUIRE) != MP_WAKEUP_NOOP) {
        if (arch_read_time() - start >= timeout) return false;
        cpu_relax();
    }

    return true;
}

static int launch_func_mp_wakeup(cpu_t *cpu, void *init_ctx, void *ptr) {
    struct mp_wakeup_ctx *ctx = ptr;
    mp_wakeup_mailbox_t *mailbox = ctx->mailbox;

    if (mailbox == NULL) {
        uintptr_t addr;
        int error = map_mmio(&addr, ctx->phys, sizeof(*mailbox), PMAP_READABLE | PMAP_WRITABLE);
        if (unlikely(error)) return error;
    }

    mp_data_t *data = ctx->data;

    if (data == NULL) {
        page_t *page = pmem_alloc_slow_and_unreliable_now(0, UINT32_MAX, 0x1000, 1);
        if (unlikely(!page)) return ENOMEM;

        data = page_to_virt(page);
        int error = init_mp_data(data, page_to_phys(page));
        if (unlikely(error)) {
            pmem_free_now(page);
            return error;
        }
        ctx->data = data;
    }

    if (!wakeup_wait_for_command(mailbox, 10 * NS_PER_MS)) return ETIMEDOUT;

    int error = init_mp_data_for_cpu(data, cpu, init_ctx);
    if (unlikely(error)) return error;

    mailbox->wakeup_vector = virt_to_phys(data);
    mailbox->apic_id = cpu->arch.apic_id;
    __atomic_store_n(&mailbox->command, MP_WAKEUP_JUMP, __ATOMIC_RELEASE);

    if (!wakeup_wait_for_command(mailbox, 10 * NS_PER_MS)) return ETIMEDOUT;

    error = mp_data_wait(data, 10 * NS_PER_MS);
    if (unlikely(error)) return error;

    return 0;
}

static void mp_wakeup_cleanup(void *ptr) {
    struct mp_wakeup_ctx *ctx = ptr;

    if (ctx->mailbox != NULL) {
        unmap_mmio((uintptr_t)ctx->mailbox, sizeof(*ctx->mailbox));
    }

    if (ctx->data != NULL) {
        cleanup_mp_data(ctx->data, virt_to_phys(ctx->data));
        pmem_free_now(virt_to_page(ctx->data));
    }

    vfree(ctx, sizeof(*ctx));
}

static event_t smp_current_online;

static void launch_cpu(
        uint32_t acpi_id,
        uint32_t apic_id,
        uint32_t flags,
        struct acpi_madt *madt,
        size_t *num_extra,
        launch_func_t func,
        void *ctx
) {
    if (apic_id == this_cpu_read(arch.apic_id)) return;

    if ((flags & (ACPI_PIC_ENABLED | ACPI_PIC_ONLINE_CAPABLE)) == 0) {
        printk("smp: cpu with apic id %u is disabled by firmware\n", apic_id);
        return;
    }

    if (apic_id > 0xff && !x86_64_cpu_features.x2apic) {
        printk("smp: apic id above 255 but x2apic is not supported\n");
        return;
    }

    size_t id = num_cpus;
    if (id >= MAX_CPUS) {
        *num_extra += 1;
        return;
    }

    cpu_t *cpu;
    int error = alloc_cpu(&cpu);
    if (unlikely(error)) {
        printk("smp: failed to allocate cpu data (%e)\n", error);
        return;
    }

    cpu->id = id;
    cpu->arch.acpi_id = acpi_id;
    cpu->arch.apic_id = apic_id;

    event_clear(&smp_current_online);

    error = func(cpu, madt, ctx);
    if (unlikely(error)) {
        printk("smp: failed to launch cpu with apic id %u (%e)\n", apic_id, error);
        free_cpu(cpu);
    }

    event_wait(&smp_current_online, 0, false);

    num_cpus = id + 1;
    slist_insert_tail(&cpus, &cpu->node);

    sched_migrate(cpu);
    smp_init_current_late();
}

static void smp_init(void) {
    uacpi_table table;
    uacpi_status status = uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &table);
    if (uacpi_unlikely_error(status)) {
        printk("smp: failed to find madt table: %s\n", uacpi_status_to_string(status));
        return;
    }

    struct acpi_madt *madt = table.ptr;

    struct acpi_entry_hdr *cur = madt->entries;
    struct acpi_entry_hdr *end = (void *)madt + madt->hdr.length;

    launch_func_t launch_func = launch_func_sipi;
    void (*launch_cleanup)(void *) = sipi_cleanup;
    void *launch_ctx = NULL;

    {
        sipi_ctx_t *ctx = vmalloc(sizeof(*ctx));
        if (unlikely(!ctx)) {
            printk("smp: failed to allocate sipi context\n");
            return;
        }
        memset(ctx, 0, sizeof(*ctx));
        launch_ctx = ctx;
    }

    while (cur < end) {
        if (cur->type == ACPI_MADT_ENTRY_TYPE_MULTIPROCESSOR_WAKEUP) {
            struct acpi_madt_multiprocessor_wakeup *entry = (void *)cur;

            launch_cleanup(launch_ctx);

            struct mp_wakeup_ctx *ctx = vmalloc(sizeof(*ctx));
            if (unlikely(!ctx)) {
                printk("smp: failed to allocate wakeup context\n");
                goto done;
            }
            memset(ctx, 0, sizeof(*ctx));

            ctx->phys = entry->mailbox_address;
            ctx->version = entry->mailbox_version;

            launch_func = launch_func_mp_wakeup;
            launch_cleanup = mp_wakeup_cleanup;
            launch_ctx = ctx;
            break;
        }

        cur = (void *)cur + cur->length;
    }

    // launch_cpu migrates itself to the launched cpu and does some work there,
    // wrap the entire thing in a migration lock to ensure it doesn't get migrated
    // away
    migrate_state_t state = migrate_lock();

    size_t num_extra = 0;

    cur = madt->entries;

    while (cur < end) {
        if (cur->type == ACPI_MADT_ENTRY_TYPE_LAPIC) {
            struct acpi_madt_lapic *entry = (void *)cur;
            launch_cpu(entry->uid, entry->id, entry->flags, madt, &num_extra, launch_func, launch_ctx);
        } else if (cur->type == ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC) {
            struct acpi_madt_x2apic *entry = (void *)cur;
            launch_cpu(entry->uid, entry->id, entry->flags, madt, &num_extra, launch_func, launch_ctx);
        }

        cur = (void *)cur + cur->length;
    }

    sched_migrate(&boot_cpu);
    migrate_unlock(state);

    launch_cleanup(launch_ctx);

    if (num_extra != 0) {
        printk("smp: ignored %U cpus (kernel supports at most %U cpus)\n", num_extra, MAX_CPUS);
    }

    printk("smp: %U cpus online\n", num_cpus);
done:
    uacpi_table_unref(&table);
}

INIT_DEFINE(x86_64_smp, smp_init);

_Noreturn void x86_64_smp_init_current(cpu_t *cpu, void *ctx) {
    x86_64_cpu_init(cpu);
    x86_64_lapic_init_local(ctx);
    smp_init_current(&smp_current_online);
}
