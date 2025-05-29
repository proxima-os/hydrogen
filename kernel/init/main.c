#include "init/main.h"
#include "arch/irq.h"
#include "arch/time.h"
#include "cpu/cpudata.h"
#include "drv/framebuffer.h" /* IWYU pragma: keep */
#include "fs/ramfs.h"
#include "fs/vfs.h"
#include "init/cmdline.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "limine.h"
#include "mem/pmem.h"
#include "mem/vmm.h"
#include "proc/event.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "sections.h"
#include "sys/exec.h"
#include "sys/transition.h"
#include "util/handle.h"
#include "util/object.h"
#include "util/panic.h"
#include "util/printk.h"
#include "util/slist.h"
#include "util/spinlock.h"
#include <hydrogen/filesystem.h>
#include <hydrogen/handle.h>
#include <hydrogen/types.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

__attribute__((used, section(".requests0"))) static LIMINE_REQUESTS_START_MARKER;
__attribute__((used, section(".requests2"))) static LIMINE_REQUESTS_END_MARKER;

LIMINE_REQ LIMINE_BASE_REVISION(3);

static slist_t kernel_tasks;
static thread_t *task_thread;
static spinlock_t kernel_tasks_lock;

static void associate_std_handle(int handle, file_t *file) {
    hydrogen_ret_t ret = namespace_add(
        current_thread->namespace,
        HYDROGEN_FILE_WRITE,
        handle,
        &file->base,
        OBJECT_FILE_DESCRIPTION,
        HYDROGEN_HANDLE_CLONE_KEEP | HYDROGEN_HANDLE_EXEC_KEEP
    );
    if (unlikely(ret.error)) panic("failed to set up standard handle %d (%e)", handle, ret.error);
    ASSERT(ret.integer == (size_t)handle);
}

static void launch_init_process(void *ctx) {
    static const char filename[] = "/sbin/init";
    static const char *envp[] = {"HOME=/root"};

    int error = namespace_create(&current_thread->namespace);
    if (unlikely(error)) panic("failed to create init process namespace (%e)", error);

    file_t *file;
    ident_t *ident = ident_get(current_thread->process);
    error = vfs_open(&file, NULL, "/dev/klog", 9, __O_WRONLY, 0, ident);
    if (unlikely(error)) panic("failed to open /dev/klog (%e)", error);

    associate_std_handle(0, file);
    associate_std_handle(1, file);
    associate_std_handle(2, file);

    file_t *image;
    error = vfs_open(&image, NULL, filename, sizeof(filename) - 1, 0, 0, ident);
    if (unlikely(error)) panic("failed to open init executable (%e)", error);

    hydrogen_string_t filename_arg = {filename, sizeof(filename) - 1};
    hydrogen_string_t envp_args[sizeof(envp) / sizeof(*envp)];

    for (size_t i = 0; i < sizeof(envp) / sizeof(*envp); i++) {
        envp_args[i].data = envp[i];
        envp_args[i].size = strlen(envp[i]);
    }

    exec_data_t data;
    error = create_exec_data(
        &data,
        current_thread->process,
        image,
        ident,
        1,
        &filename_arg,
        sizeof(envp) / sizeof(*envp),
        envp_args,
        false
    );
    ident_deref(ident);
    if (unlikely(error)) panic("failed to launch init process (%e)", error);

    vfs_umask(current_thread->process, 022);
    vmm_switch(data.vmm);

    exec_finalize(&data);
    arch_enter_user_mode(data.pc, data.sp);
}

static void run_init_task(const char *target_name, void *id, init_task_t *task, init_task_t **target) {
    if (task->run_id == id) return;

    if (task->target == id) panic("init(%s): recursive dependencies in %s", target_name, task->name);
    if (target != task->target) panic("init(%s): dependency to %s crosses target barrier", target_name, task->name);
    task->target = id;

    for (size_t i = 0; i < task->num_dependencies; i++) {
        run_init_task(target_name, id, task->dependencies[i], target);
    }

    // use raw printk calls to set up the terminal in such a way that the running text is shown
    // on consoles but as soon as something else gets printed it disappears and gets overwritten
    printk_state_t state = printk_lock();
    printk_raw_format("init(%s): running task %s...", target_name, task->name);
    printk_raw_flush();
    printk_raw_format("\r\e[2K");
    printk_unlock(state);

    uint64_t start = arch_read_time();
    task->func();
    uint64_t delta = arch_read_time() - start;

    state = printk_lock();
    printk_raw_format("init(%s): task %s took ", target_name, task->name);

    if (delta < NS_PER_US) printk_raw_format("%U ns\n", delta);
    else if (delta < NS_PER_MS) printk_raw_format("%U.%U us\n", delta / 1000, delta % 1000 / 100);
    else if (delta < NS_PER_SEC) printk_raw_format("%U.%U ms\n", delta / 1000000, delta % 1000000 / 100000);
    else printk_raw_format("%U.%U s\n", delta / 1000000000, delta % 1000000000 / 10000000);

    printk_raw_flush();
    printk_unlock(state);

    task->run_id = id;
    task->target = target;
}

static void run_init_target(const char *target_name, void *id, init_task_t **start, init_task_t **end) {
    init_task_t **target = start;

    while (start < end) {
        run_init_task(target_name, id, *start, target);
        start++;
    }
}

#define RUN_INIT_TARGET(name, pretty, id)                                            \
    ({                                                                               \
        extern init_task_t *__inittask_start_##name[], *__inittask_end_##name[];     \
        run_init_target(pretty, id, __inittask_start_##name, __inittask_end_##name); \
    })

static void kernel_init(void *ctx) {
    RUN_INIT_TARGET(dflt, "default", NULL);

    // the idle thread still holds a reference to this thread, but it can't free it itself because that might sleep
    obj_deref(&current_thread->base);

    pmem_stats_t stats = pmem_get_stats();
    printk(
        "mem: %zK total, %zK available, %zK free\n",
        stats.total * (PAGE_SIZE / 1024),
        stats.available * (PAGE_SIZE / 1024),
        stats.free * (PAGE_SIZE / 1024)
    );

    int error = proc_clone(&init_process);
    if (unlikely(error)) panic("failed to create init process (%e)", error);

    thread_t *thread;
    error = sched_create_thread(&thread, launch_init_process, NULL, NULL, init_process, THREAD_USER);
    if (unlikely(error)) panic("failed to create init process main thread (%d)", error);

    task_thread = current_thread;
    sched_wake(thread);
    obj_deref(&thread->base);

    for (;;) {
        irq_state_t state = spin_acq(&kernel_tasks_lock);
        task_t *task = SLIST_REMOVE_HEAD(kernel_tasks, task_t, node);
        if (!task) sched_prepare_wait(false);
        spin_rel(&kernel_tasks_lock, state);
        if (!task) {
            sched_perform_wait(0);
            continue;
        }

        task->func(task);
    }
}

USED _Noreturn void kernel_main(void) {
    extern init_task_t *__inittask_start_early[];

    parse_command_line();

    // run framebuffer task explicitly to get output as early as possible
    run_init_task("early", NULL, INIT_REFERENCE(framebuffer_printk), __inittask_start_early);
    RUN_INIT_TARGET(early, "early", NULL);

    thread_t *init_thread;
    int error = sched_create_thread(&init_thread, kernel_init, NULL, &boot_cpu, &kernel_process, 0);
    if (unlikely(error)) panic("failed to create init thread (%e)", error);
    sched_wake(init_thread);
    sched_idle();
}

_Noreturn void smp_init_current(event_t *event) {
    RUN_INIT_TARGET(earlyap, "early-ap", get_current_cpu());
    if (event != NULL) event_signal(event);
    sched_idle();
}

void smp_init_current_late(void) {
    RUN_INIT_TARGET(dfltap, "default-ap", get_current_cpu());
}

void schedule_kernel_task(task_t *task) {
    irq_state_t state = spin_acq(&kernel_tasks_lock);
    slist_insert_tail(&kernel_tasks, &task->node);
    spin_rel(&kernel_tasks_lock, state);
}

static void mount_rootfs(void) {
    filesystem_t *fs;
    int error = ramfs_create(&fs, 0755);
    if (unlikely(error)) panic("failed to create rootfs (%e)", error);

    error = vfs_mount(NULL, "/", 1, fs);
    if (unlikely(error)) panic("failed to mount rootfs (%e)", error);

    error = vfs_chroot(current_thread->process, NULL, "/", 1);
    if (unlikely(error)) panic("failed to chroot to new root (%e)", error);

    error = vfs_create(NULL, "/dev", 4, HYDROGEN_DIRECTORY, 0755, NULL);
    if (unlikely(error)) panic("failed to create /dev (%e)", error);

    filesystem_t *devfs;
    error = ramfs_create(&devfs, 0755);
    if (unlikely(error)) panic("failed to create /dev filesystem (%e)", error);

    error = vfs_mount(NULL, "/dev", 4, fs);
    if (unlikely(error)) panic("failed to mount /dev (%e)", error);
}

INIT_DEFINE(mount_rootfs, mount_rootfs, INIT_REFERENCE(vfs));

static void verify_loader_revision(void) {
    if (!LIMINE_BASE_REVISION_SUPPORTED) {
        panic("loader does not support requested base revision");
    }
}

INIT_DEFINE_EARLY(verify_loader_revision, verify_loader_revision);
