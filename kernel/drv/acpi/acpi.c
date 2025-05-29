#include "drv/acpi/acpi.h"
#include "arch/pmap.h"
#include "cpu/cpudata.h"
#include "fs/vfs.h"
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
#include "proc/process.h"
#include "sections.h"
#include "string.h"
#include "uacpi/kernel_api.h"
#include "uacpi/platform/types.h"
#include "uacpi/status.h"
#include "uacpi/types.h"
#include "uacpi/uacpi.h"
#include "util/object.h"
#include "util/printk.h"
#include "util/spinlock.h"
#include <hydrogen/fcntl.h>
#include <hydrogen/filesystem.h>
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

static void create_acpi_devices(void) {
    if (!have_acpi_tables) return;

    int error = vfs_create(NULL, "/dev/acpi", 9, HYDROGEN_DIRECTORY, 0755, NULL);
    if (unlikely(error)) {
        printk("acpi: failed to create /dev/acpi (%e)\n", error);
        return;
    }

    file_t *file;
    ident_t *ident = ident_get(current_thread->process);
    error = vfs_open(&file, NULL, "/dev/acpi/rsdp", 14, __O_WRONLY | __O_CREAT | __O_EXCL, 0600, ident);
    ident_deref(ident);
    if (unlikely(error)) {
        printk("acpi: failed to create /dev/acpi/rsdp (%e)\n", error);
        return;
    }

    unsigned char buffer[32];
    size_t size = sprintk(buffer, sizeof(buffer), "0x%X\n", rsdp_phys);
    ASSERT(size <= sizeof(buffer));

    error = vfs_pwrite_full(file, buffer, size, 0);
    obj_deref(&file->base);
    if (unlikely(error)) {
        printk("acpi: failed to create /dev/acpi/rsdp (%e)", error);
        return;
    }
}

INIT_DEFINE(create_acpi_devices, create_acpi_devices, INIT_REFERENCE(mount_rootfs));

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
