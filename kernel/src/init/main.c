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
#include "limine.h"
#include "mem/obj/pmem.h"
#include "mem/pmm.h"
#include "mem/vmm.h"
#include "sections.h"
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

static pmem_vm_object_t ram_object;

static void kernel_init(UNUSED void *ctx) {
    init_sched_late();
    init_smp();
    reclaim_loader_pages();
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

    hydrogen_init_info_t init_info = {};
    init_info.major = HYDROGEN_INIT_INFO_MAJOR_VERSION;
    init_info.minor = HYDROGEN_INIT_INFO_MINOR_VERSION;

    // Create handle for kernel log
    error = create_handle(&klog_object, -1, &init_info.log_handle);
    if (unlikely(error)) panic("failed to create kernel log handle (%d)", error);

    // Create handle for physical memory
    pmem_vm_obj_init(&ram_object, 0, cpu_features.paddr_mask + 1);
    error = create_handle(&ram_object.base.base, (uint64_t)-1 & ~HYDROGEN_MEMORY_RIGHT_PRIVATE, &init_info.ram_handle);
    if (unlikely(error)) panic("failed to create ram handle (%d)", error);

    // Create handle for I/O access
    error = create_handle(&io_object, -1, &init_info.io_handle);
    if (unlikely(error)) panic("failed to create i/o handle (%d)", error);

    // Copy init info to userspace stack
    stack_top -= sizeof(init_info);
    stack_top &= ~15;
    error = memcpy_user((void *)stack_top, &init_info, sizeof(init_info));
    if (unlikely(error)) panic("failed to copy init info to user memory (%d)", error);

    // Finalize kernel initialization
    pmm_stats_t stats = pmm_get_stats();
    printk("mem: %Uk total, %Uk available, %Uk free\n",
           stats.total << (PAGE_SHIFT - 10),
           stats.available << (PAGE_SHIFT - 10),
           stats.free << (PAGE_SHIFT - 10));

    printk("hydrogen: starting userspace init thread\n");
    enter_user_mode(vdso_addr + vdso_image.entry, stack_top);
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
