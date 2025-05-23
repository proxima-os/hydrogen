#include "drv/acpi/acpi.h"
#include "arch/gsi.h"
#include "arch/idle.h"
#include "arch/pio.h"
#include "arch/pmap.h"
#include "arch/time.h"
#include "cpu/cpudata.h"
#include "drv/pci/config-access.h"
#include "init/main.h" /* IWYU pragma: keep */
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "limine.h"
#include "mem/kvmm.h"
#include "mem/memmap.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/vmalloc.h"
#include "proc/event.h"
#include "proc/mutex.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "proc/semaphore.h"
#include "sections.h"
#include "string.h"
#include "uacpi/event.h"
#include "uacpi/kernel_api.h"
#include "uacpi/platform/arch_helpers.h"
#include "uacpi/platform/types.h"
#include "uacpi/status.h"
#include "uacpi/types.h"
#include "uacpi/uacpi.h"
#include "util/object.h"
#include "util/printk.h"
#include "util/spinlock.h"
#include "util/time.h"
#include <stddef.h>
#include <stdint.h>

#define EARLY_TABLE_BUFFER_SIZE 16384

static uint64_t rsdp_phys;
static bool have_acpi_tables;

static LIMINE_REQ struct limine_rsdp_request rsdp_req = {.id = LIMINE_RSDP_REQUEST};

static void acpi_tables_init(void) {
    if (!rsdp_req.response) {
        printk("acpi: no response to rsdp request\n");
        return;
    }

    rsdp_phys = rsdp_req.response->address;

    void *buffer = vmalloc(EARLY_TABLE_BUFFER_SIZE);
    if (unlikely(!buffer)) {
        printk("acpi: failed to allocate early table buffer\n");
        return;
    }

    uacpi_status status = uacpi_setup_early_table_access(buffer, EARLY_TABLE_BUFFER_SIZE);
    if (uacpi_unlikely_error(status)) {
        printk("acpi: initialization failed: %s\n", uacpi_status_to_string(status));
        vfree(buffer, EARLY_TABLE_BUFFER_SIZE);
        return;
    }

    have_acpi_tables = true;
}

INIT_DEFINE_EARLY(acpi_tables, acpi_tables_init, INIT_REFERENCE(memory), INIT_REFERENCE(verify_loader_revision));

static void acpi_init(void) {
    if (!have_acpi_tables) return;

    uacpi_status status = uacpi_initialize(0);
    if (uacpi_unlikely_error(status)) {
        printk("acpi: failed to initialize uacpi: %s\n", uacpi_status_to_string(status));
        return;
    }

    status = uacpi_namespace_load();
    if (uacpi_unlikely_error(status)) {
        printk("acpi: failed to load namespace: %s\n", uacpi_status_to_string(status));
        return;
    }

    status = uacpi_namespace_initialize();
    if (uacpi_unlikely_error(status)) {
        printk("acpi: failed to initialize namespace: %s\n", uacpi_status_to_string(status));
        return;
    }

    status = uacpi_finalize_gpe_initialization();
    if (uacpi_unlikely_error(status)) {
        printk("acpi: failed to initialize gpes: %s\n", uacpi_status_to_string(status));
        return;
    }
}

INIT_DEFINE(
        acpi,
        acpi_init,
        INIT_REFERENCE(scheduler),
        INIT_REFERENCE(enable_interrupts),
        INIT_REFERENCE(pci_config_access)
);

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr *out_rsdp_address) {
    *out_rsdp_address = rsdp_phys;
    return UACPI_STATUS_OK;
}

static page_t *get_scratch_page(void) {
    static page_t *page;
    static spinlock_t lock;

    page_t *p = __atomic_load_n(&page, __ATOMIC_ACQUIRE);

    if (!p) {
        spin_acq_noirq(&lock);

        p = __atomic_load_n(&page, __ATOMIC_ACQUIRE);

        if (!p) {
            p = pmem_alloc_now();

            if (likely(p)) {
                memset(page_to_virt(p), 0, PAGE_SIZE);
                __atomic_store_n(&page, p, __ATOMIC_RELEASE);
            }
        }

        spin_rel_noirq(&lock);
    }

    return p;
}

static bool handle_kernel_area(uintptr_t *cur, uint64_t *addr, size_t *len, uint64_t gap_head) {
    size_t delta = gap_head - *addr;
    if (delta > *len) delta = *len;

    printk("acpi: warning: firmware tried to map kernel-owned memory (0x%X-0x%X)\n", *addr, *addr + delta - 1);

    size_t cur_map = (delta + (*addr & PAGE_MASK) + PAGE_MASK) & ~PAGE_MASK;

    page_t *page = get_scratch_page();
    if (unlikely(!page)) return false;
    uint64_t phys = page_to_phys(page);

    do {
        pmap_map(NULL, *cur, phys, PAGE_SIZE, PMAP_READABLE | PMAP_WRITABLE);
        *cur += PAGE_SIZE;
        cur_map -= PAGE_SIZE;
    } while (cur_map != 0);

    addr += delta;
    *len -= delta;
    return true;
}

void *uacpi_kernel_map(uacpi_phys_addr addr, uacpi_size len) {
    if (unlikely(len == 0)) return (void *)_Alignof(max_align_t);

    size_t offset = addr & PAGE_MASK;
    size_t maplen = (len + offset + PAGE_MASK) & ~PAGE_MASK;
    if (unlikely(maplen < len)) return NULL;

    uintptr_t virt = kvmm_alloc(maplen);
    if (unlikely(virt == 0)) return NULL;
    if (unlikely(!pmap_prepare(NULL, virt, maplen))) goto err;

    uintptr_t cur = virt;

    do {
        uint64_t gap_head, gap_tail;

        if (next_owned_ram_gap(addr, &gap_head, &gap_tail)) {
            if (addr < gap_head) {
                if (!handle_kernel_area(&cur, &addr, &len, gap_head)) goto err2;
                if (len == 0) break;
            }

            ASSERT(addr <= gap_tail);

            size_t cur_len = gap_tail - addr + 1;
            if (cur_len > len) cur_len = len;

            int cflag = is_area_ram(addr, addr + cur_len - 1) ? 0 : PMAP_CACHE_UC;

            size_t offset = addr & PAGE_MASK;
            size_t cur_map = (cur_len + offset + PAGE_MASK) & ~PAGE_MASK;

            pmap_map(NULL, cur, addr - offset, cur_map, PMAP_READABLE | PMAP_WRITABLE | cflag);

            cur += cur_map;
            addr += cur_len;
            len -= cur_len;
            if (len == 0) break;
        } else {
            gap_head = addr + len;
        }

        if (!handle_kernel_area(&cur, &addr, &len, gap_head)) goto err2;
    } while (len != 0);

    return (void *)(virt + offset);
err2:
    pmap_unmap(NULL, virt, maplen);
err:
    kvmm_free(virt, maplen);
    return NULL;
}

void uacpi_kernel_unmap(void *addr, uacpi_size len) {
    uintptr_t virt = (uintptr_t)addr;
    size_t offset = virt & PAGE_MASK;
    virt -= offset;
    size_t size = (len + offset + PAGE_MASK) & ~PAGE_MASK;

    pmap_unmap(NULL, virt, size);
    kvmm_free(virt, size);
}

void uacpi_kernel_log(uacpi_log_level level, const uacpi_char *str) {
    const char *lstr;

    switch (level) {
    case UACPI_LOG_DEBUG: lstr = "debug"; break;
    case UACPI_LOG_TRACE: lstr = "trace"; break;
    case UACPI_LOG_INFO: lstr = "info"; break;
    case UACPI_LOG_WARN: lstr = "warning"; break;
    case UACPI_LOG_ERROR: lstr = "error"; break;
    default: UNREACHABLE();
    }

    printk("acpi: [uacpi %s] %s", lstr, str);
}

void *uacpi_kernel_alloc(uacpi_size size) {
    return vmalloc(size);
}

void uacpi_kernel_free(void *mem, uacpi_size size_hint) {
    vfree(mem, size_hint);
}

uacpi_handle uacpi_kernel_create_spinlock(void) {
    spinlock_t *lock = vmalloc(sizeof(*lock));
    if (unlikely(!lock)) return NULL;
    memset(lock, 0, sizeof(*lock));
    return lock;
}

void uacpi_kernel_free_spinlock(uacpi_handle handle) {
    vfree(handle, sizeof(spinlock_t));
}

uacpi_cpu_flags uacpi_kernel_lock_spinlock(uacpi_handle handle) {
    return spin_acq(handle);
}

void uacpi_kernel_unlock_spinlock(uacpi_handle handle, uacpi_cpu_flags flags) {
    spin_rel(handle, flags);
}

uacpi_status uacpi_kernel_schedule_work(uacpi_work_type type, uacpi_work_handler handler, uacpi_handle ctx) {
    return UACPI_STATUS_UNIMPLEMENTED;
}

uacpi_status uacpi_kernel_wait_for_work_completion(void) {
    return UACPI_STATUS_UNIMPLEMENTED;
}

typedef struct {
    gsi_handler_t gsi;
    uacpi_interrupt_handler handler;
    uacpi_handle ctx;
    semaphore_t sema;
    size_t pending;
    event_t terminated;
} acpi_irq_t;

static bool handle_acpi_irq(void *ptr) {
    acpi_irq_t *irq = ptr;
    __atomic_fetch_add(&irq->pending, 1, __ATOMIC_RELAXED);
    sema_signal(&irq->sema);
    return true;
}

static void acpi_irq_thread(void *ptr) {
    acpi_irq_t *irq = ptr;

    for (;;) {
        sema_wait(&irq->sema, 0, false);
        if (__atomic_fetch_sub(&irq->pending, 1, __ATOMIC_RELAXED) == 0) break;
        irq->handler(irq->ctx);
    }

    event_signal(&irq->terminated);
}

uacpi_status uacpi_kernel_install_interrupt_handler(
        uacpi_u32 irq,
        uacpi_interrupt_handler handler,
        uacpi_handle ctx,
        uacpi_handle *out_irq_handle
) {
    acpi_irq_t *data = vmalloc(sizeof(*data));
    if (unlikely(!data)) return UACPI_STATUS_OUT_OF_MEMORY;
    memset(data, 0, sizeof(*data));

    data->handler = handler;
    data->ctx = ctx;

    int error = gsi_install(&data->gsi, irq, handle_acpi_irq, data, GSI_EDGE_TRIGGERED | GSI_ACTIVE_HIGH);
    if (unlikely(error)) {
        vfree(data, sizeof(*data));
        return UACPI_STATUS_INTERNAL_ERROR;
    }

    thread_t *thread;
    error = sched_create_thread(&thread, acpi_irq_thread, data, NULL, &kernel_process, 0);
    if (unlikely(error)) {
        gsi_uninstall(&data->gsi);
        vfree(data, sizeof(*data));
        return UACPI_STATUS_INTERNAL_ERROR;
    }
    sched_wake(thread);
    obj_deref(&thread->base);

    *out_irq_handle = data;
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_uninstall_interrupt_handler(uacpi_interrupt_handler handler, uacpi_handle irq_handle) {
    acpi_irq_t *data = irq_handle;
    gsi_uninstall(&data->gsi);

    __atomic_store_n(&data->handler, NULL, __ATOMIC_RELAXED);
    sema_signal(&data->sema);
    event_wait(&data->terminated, 0, false);

    vfree(data, sizeof(*data));
    return UACPI_STATUS_OK;
}

uacpi_handle uacpi_kernel_create_event(void) {
    semaphore_t *sema = vmalloc(sizeof(*sema));
    if (unlikely(!sema)) return NULL;
    memset(sema, 0, sizeof(*sema));
    return sema;
}

void uacpi_kernel_free_event(uacpi_handle handle) {
    vfree(handle, sizeof(semaphore_t));
}

uacpi_bool uacpi_kernel_wait_for_event(uacpi_handle handle, uacpi_u16 timeout) {
    if (timeout == 0) return sema_try_wait(handle);
    if (timeout == 0xffff) return likely(!sema_wait(handle, 0, false));
    return likely(!sema_wait(handle, arch_read_time() + timeout * NS_PER_MS, false));
}

void uacpi_kernel_signal_event(uacpi_handle handle) {
    sema_signal(handle);
}

void uacpi_kernel_reset_event(uacpi_handle handle) {
    sema_reset(handle);
}

uacpi_handle uacpi_kernel_create_mutex(void) {
    mutex_t *mutex = vmalloc(sizeof(*mutex));
    if (unlikely(!mutex)) return NULL;
    memset(mutex, 0, sizeof(*mutex));
    return mutex;
}

void uacpi_kernel_free_mutex(uacpi_handle handle) {
    vfree(handle, sizeof(mutex_t));
}

uacpi_status uacpi_kernel_acquire_mutex(uacpi_handle handle, uacpi_u16 timeout) {
    if (timeout == 0) return mutex_try_acq(handle) ? UACPI_STATUS_OK : UACPI_STATUS_TIMEOUT;
    return likely(!mutex_acq(handle, timeout == 0xffff ? 0 : arch_read_time() + timeout * NS_PER_MS, false))
                   ? UACPI_STATUS_OK
                   : UACPI_STATUS_TIMEOUT;
}

void uacpi_kernel_release_mutex(uacpi_handle handle) {
    mutex_rel(handle);
}

void uacpi_kernel_stall(uacpi_u8 usec) {
    uint64_t deadline = arch_read_time() + (uint64_t)usec * NS_PER_US;
    while (arch_read_time() < deadline) cpu_relax();
}

uacpi_u64 uacpi_kernel_get_nanoseconds_since_boot(void) {
    return arch_read_time();
}

void uacpi_kernel_sleep(uacpi_u64 msec) {
    sched_prepare_wait(false);
    sched_perform_wait(arch_read_time() + msec * NS_PER_MS);
}

uacpi_status uacpi_kernel_handle_firmware_request(uacpi_firmware_request *request) {
    return UACPI_STATUS_UNIMPLEMENTED;
}

_Static_assert(sizeof(pci_config_t) <= sizeof(uacpi_handle), "pci_config_t too large");

uacpi_status uacpi_kernel_pci_device_open(uacpi_pci_address address, uacpi_handle *out_handle) {
    pci_address_t addr = {address.segment, address.bus, address.device, address.function};
    pci_config_t config;
    if (unlikely(!pci_config_get(&addr, &config))) return UACPI_STATUS_NOT_FOUND;

    memcpy(out_handle, &config, sizeof(config));
    return UACPI_STATUS_OK;
}

void uacpi_kernel_pci_device_close(uacpi_handle handle) {
}

uacpi_status uacpi_kernel_pci_read8(uacpi_handle device, uacpi_size offset, uacpi_u8 *value) {
    pci_config_t config;
    memcpy(&config, &device, sizeof(config));
    *value = pci_read8(config, offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_read16(uacpi_handle device, uacpi_size offset, uacpi_u16 *value) {
    pci_config_t config;
    memcpy(&config, &device, sizeof(config));
    *value = pci_read16(config, offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_read32(uacpi_handle device, uacpi_size offset, uacpi_u32 *value) {
    pci_config_t config;
    memcpy(&config, &device, sizeof(config));
    *value = pci_read32(config, offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_write8(uacpi_handle device, uacpi_size offset, uacpi_u8 value) {
    pci_config_t config;
    memcpy(&config, &device, sizeof(config));
    pci_write8(config, offset, value);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_write16(uacpi_handle device, uacpi_size offset, uacpi_u16 value) {
    pci_config_t config;
    memcpy(&config, &device, sizeof(config));
    pci_write16(config, offset, value);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_write32(uacpi_handle device, uacpi_size offset, uacpi_u32 value) {
    pci_config_t config;
    memcpy(&config, &device, sizeof(config));
    pci_write32(config, offset, value);
    return UACPI_STATUS_OK;
}

_Static_assert(sizeof(pio_addr_t) <= sizeof(uacpi_handle), "uacpi_io_addr too large");

uacpi_status uacpi_kernel_io_map(uacpi_io_addr base, uacpi_size len, uacpi_handle *out_handle) {
    if (unlikely(!ARCH_HAS_PIO)) return UACPI_STATUS_NOT_FOUND;
    if (unlikely(len == 0)) return UACPI_STATUS_OK;

    uacpi_io_addr tail = base + (len - 1);
    if (unlikely(tail < base)) return UACPI_STATUS_NOT_FOUND;
    if (unlikely(tail > ARCH_PIO_MAX)) return UACPI_STATUS_NOT_FOUND;

    pio_addr_t addr = base;
    memcpy(out_handle, &addr, sizeof(addr));
    return UACPI_STATUS_OK;
}

void uacpi_kernel_io_unmap(uacpi_handle handle) {
}

uacpi_status uacpi_kernel_io_read8(uacpi_handle handle, uacpi_size offset, uacpi_u8 *out_value) {
    pio_addr_t addr;
    memcpy(&addr, &handle, sizeof(addr));
    *out_value = pio_read8(addr + offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_read16(uacpi_handle handle, uacpi_size offset, uacpi_u16 *out_value) {
    pio_addr_t addr;
    memcpy(&addr, &handle, sizeof(addr));
    *out_value = pio_read16(addr + offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_read32(uacpi_handle handle, uacpi_size offset, uacpi_u32 *out_value) {
    pio_addr_t addr;
    memcpy(&addr, &handle, sizeof(addr));
    *out_value = pio_read32(addr + offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_write8(uacpi_handle handle, uacpi_size offset, uacpi_u8 in_value) {
    pio_addr_t addr;
    memcpy(&addr, &handle, sizeof(addr));
    pio_write8(addr + offset, in_value);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_write16(uacpi_handle handle, uacpi_size offset, uacpi_u16 in_value) {
    pio_addr_t addr;
    memcpy(&addr, &handle, sizeof(addr));
    pio_write16(addr + offset, in_value);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_write32(uacpi_handle handle, uacpi_size offset, uacpi_u32 in_value) {
    pio_addr_t addr;
    memcpy(&addr, &handle, sizeof(addr));
    pio_write32(addr + offset, in_value);
    return UACPI_STATUS_OK;
}

uacpi_thread_id uacpi_kernel_get_thread_id(void) {
    return current_thread;
}
