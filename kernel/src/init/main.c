#include "cpu/cpu.h"
#include "cpu/exc.h"
#include "cpu/idt.h"
#include "cpu/lapic.h"
#include "cpu/xsave.h"
#include "drv/acpi.h"
#include "drv/pic.h"
#include "hydrogen/error.h"
#include "hydrogen/handle.h"
#include "hydrogen/init.h"
#include "hydrogen/memory.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "limine.h"
#include "mem/obj/pmem.h"
#include "mem/pmm.h"
#include "mem/vmm.h"
#include "sections.h"
#include "string.h"
#include "sys/elf.h"
#include "sys/syscall.h"
#include "sys/usermem.h"
#include "sys/vdso.h"
#include "thread/sched.h"
#include "time/time.h"
#include "util/handle.h"
#include "util/io.h"
#include "util/logging.h"
#include "util/object.h"
#include "util/panic.h"
#include <stdint.h>

#define INIT_STACK_SIZE 0x10000

__attribute__((used, section(".requests0"))) static LIMINE_REQUESTS_START_MARKER;
__attribute__((used, section(".requests2"))) static LIMINE_REQUESTS_END_MARKER;

LIMINE_REQ LIMINE_BASE_REVISION(3);
static LIMINE_REQ struct limine_module_request module_req = {.id = LIMINE_MODULE_REQUEST};

static pmem_vm_object_t ram_object;

static void create_init_info(hydrogen_init_info_t *info) {
    info->major = HYDROGEN_INIT_INFO_MAJOR_VERSION;
    info->minor = HYDROGEN_INIT_INFO_MINOR_VERSION;

    // Create handle for kernel log
    hydrogen_error_t error = create_handle(&klog_object, -1, &info->log_handle);
    if (unlikely(error)) panic("failed to create kernel log handle (%d)", error);

    // Create handle for physical memory
    pmem_vm_obj_init(&ram_object, 0, cpu_features.paddr_mask + 1);
    error = create_handle(&ram_object.base.base, (uint64_t)-1 & ~HYDROGEN_MEMORY_RIGHT_PRIVATE, &info->ram_handle);
    if (unlikely(error)) panic("failed to create ram handle (%d)", error);

    // Create handle for I/O access
    error = create_handle(&io_object, -1, &info->io_handle);
    if (unlikely(error)) panic("failed to create i/o handle (%d)", error);
}

static const uint8_t wanted_elf_ident[] = {0x7f, 'E', 'L', 'F', ELF_CLASS, ELF_DATA, ELF_VERSION};

static uintptr_t map_init_image(hydrogen_init_info_t *info) {
    struct limine_module_response *modules = module_req.response;
    if (!modules) panic("no response to module request");
    if (modules->module_count == 0) panic("no modules passed to kernel");
    struct limine_file *module = modules->modules[0];
    elf_header_t *header = module->address;

    if (memcmp(header->ident, wanted_elf_ident, sizeof(wanted_elf_ident))) panic("invalid init image");
    if (header->machine != ELF_MACHINE || header->version != ELF_VERSION) panic("invalid init image");
    if (header->type != ET_EXEC && header->type != ET_DYN) panic("invalid init image");

    uintptr_t min_vaddr = UINTPTR_MAX;
    uintptr_t max_vaddr = 0;

    for (size_t i = 0; i < header->phnum; i++) {
        elf_segment_t *segment = module->address + header->phoff + i * header->phentsize;
        if (segment->type != PT_LOAD) continue;

        uintptr_t start = segment->vaddr & ~PAGE_MASK;
        uintptr_t end = (segment->vaddr + segment->memsz + PAGE_MASK) & ~PAGE_MASK;

        if (start < min_vaddr) min_vaddr = start;
        if (end > max_vaddr) max_vaddr = end;
    }

    if (min_vaddr > max_vaddr) panic("no loadable segments in init image");

    uintptr_t addr = min_vaddr;
    hydrogen_error_t error = hydrogen_vm_map(
            NULL,
            &addr,
            max_vaddr - min_vaddr,
            header->type == ET_EXEC ? HYDROGEN_MEM_EXACT : 0,
            NULL,
            0
    );
    if (unlikely(error)) panic("failed to allocate init image area (%d)", error);
    intptr_t slide = (intptr_t)addr - (intptr_t)min_vaddr;

    for (size_t i = 0; i < header->phnum; i++) {
        elf_segment_t *segment = module->address + header->phoff + i * header->phentsize;
        if (segment->type != PT_LOAD) continue;

        uintptr_t start = segment->vaddr & ~PAGE_MASK;
        uintptr_t end = (segment->vaddr + segment->memsz + PAGE_MASK) & ~PAGE_MASK;
        uintptr_t addr = start + slide;
        size_t size = end - start;
        size_t offset = virt_to_phys(module->address) + (segment->offset & ~PAGE_MASK);

        hydrogen_mem_flags_t flags = HYDROGEN_MEM_EXACT | HYDROGEN_MEM_OVERWRITE | HYDROGEN_MEM_SHARED;
        if (segment->flags & PF_R) flags |= HYDROGEN_MEM_READ;
        if (segment->flags & PF_W) flags |= HYDROGEN_MEM_WRITE;
        if (segment->flags & PF_X) flags |= HYDROGEN_MEM_EXEC;

        if (segment->filesz) {
            if ((segment->vaddr & PAGE_MASK) != (segment->offset & PAGE_MASK)) {
                panic("init image segment vaddr and offset do not have the same page offset");
            }

            size_t cur = (segment->filesz + PAGE_MASK) & ~PAGE_MASK;

            error = hydrogen_vm_map(NULL, &addr, cur, flags, info->ram_handle, offset);
            if (unlikely(error)) panic("failed to map init image segment (%d)", error);

            addr += cur;
            size -= cur;
        }

        if (size) {
            error = hydrogen_vm_map(NULL, &addr, size, flags & ~HYDROGEN_MEM_SHARED, NULL, 0);
            if (unlikely(error)) panic("failed to map init image segment (%d)", error);
        }
    }

    size_t size = strlen(module->cmdline) + 1;
    size_t pgsize = (size + PAGE_MASK) & ~PAGE_MASK;

    uintptr_t cmd_addr = 0;
    error = hydrogen_vm_map(NULL, &cmd_addr, pgsize, HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE, NULL, 0);
    if (unlikely(error)) panic("failed to map init command line (%d)", error);
    info->command_line = (char *)cmd_addr;

    error = memcpy_user(info->command_line, module->cmdline, size);
    if (unlikely(error)) panic("failed to copy init command line to user memory (%d)", error);

    return header->entry + slide;
}

static void kernel_init(UNUSED void *ctx) {
    init_sched_late();
    init_smp();
    init_vdso();
    init_syscall();

    // Create a namespace for this thread. Most things using handles will page fault before this point.
    hydrogen_error_t error = create_namespace_raw(&current_thread->namespace);
    if (unlikely(error)) panic("failed to create init namespace (%d)", error);

    uintptr_t vdso_addr;

    // Create an address space for this thread
    {
        hydrogen_handle_t handle;
        error = hydrogen_vm_create(&handle);
        if (unlikely(error)) panic("failed to create init address space (%d)", error);

        error = hydrogen_vm_map_vdso(handle, &vdso_addr);
        if (unlikely(error)) panic("failed to map init thread vdso (%d)", error);

        error = get_vm(handle, &current_thread->address_space, VM_SWITCH_RIGHTS);
        if (unlikely(error)) panic("failed to resolve init address space (%d)", error);
        vm_switch(current_thread->address_space);

        hydrogen_handle_close(NULL, handle);
    }

    // Create the userspace stack
    uintptr_t stack_addr = 0;
    error = hydrogen_vm_map(NULL, &stack_addr, PAGE_SIZE + INIT_STACK_SIZE, 0, NULL, 0);
    if (unlikely(error)) panic("failed to allocate init thread stack (%d)", error);

    uintptr_t map_addr = stack_addr + PAGE_SIZE;
    error = hydrogen_vm_map(
            NULL,
            &map_addr,
            INIT_STACK_SIZE,
            HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE | HYDROGEN_MEM_EXACT | HYDROGEN_MEM_OVERWRITE,
            NULL,
            0
    );
    if (unlikely(error)) panic("failed to map init thread stack (%d)", error);
    uintptr_t stack_top = map_addr + INIT_STACK_SIZE;

    hydrogen_init_info_t init_info = {.vdso_base = (const void *)vdso_addr};
    create_init_info(&init_info);
    stack_top -= sizeof(init_info);
    stack_top &= ~15;
    error = memcpy_user((void *)stack_top, &init_info, sizeof(init_info));
    if (unlikely(error)) panic("failed to copy init info to user memory (%d)", error);

    // Map init image
    uintptr_t entry = map_init_image(&init_info);

    // Finalize kernel initialization
    reclaim_loader_pages();
    pmm_stats_t stats = pmm_get_stats();
    printk("mem: %Uk total, %Uk available, %Uk free\n",
           stats.total << (PAGE_SHIFT - 10),
           stats.available << (PAGE_SHIFT - 10),
           stats.free << (PAGE_SHIFT - 10));

    printk("hydrogen: starting userspace init thread\n");
    enter_user_mode(entry, stack_top);
}

USED _Noreturn void kernel_main(void) {
    detect_cpu_features();
    init_idt();
    init_exceptions();
    init_cpu(NULL);
    init_pmm();
    init_usermem();
    init_fb_log();
    init_acpi();
    init_lapic_bsp();
    init_lapic();
    init_pic();
    init_time();
    init_time_local();
    init_sched_global();
    init_sched_early();
    init_xsave();
    init_syscall_cpu();

    thread_t *init_thread;
    hydrogen_error_t error = sched_create(&init_thread, kernel_init, NULL, NULL);
    if (unlikely(error)) panic("failed to create init thread (%d)", error);
    sched_wake(init_thread);
    obj_deref(&init_thread->base);

    sched_idle();
}
