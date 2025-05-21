kernel_c_flags += ['-DLIMINE_API_REVISION=3']
kernel_include += include_directories('include')
kernel_sources += files(
    'cpu/cpudata.c',
    'cpu/smp.c',
    'drv/framebuffer.c',
    'fs/fifo.c',
    'fs/ramfs.c',
    'fs/vfs.c',
    'init/cmdline.c',
    'init/initrd.c',
    'init/main.c',
    'mem/object/anonymous.c',
    'mem/kmalloc.c',
    'mem/kvmm.c',
    'mem/memmap.c',
    'mem/pmap.c',
    'mem/pmem.c',
    'mem/vmalloc.c',
    'mem/vmm.c',
    'proc/event.c',
    'proc/mutex.c',
    'proc/process.c',
    'proc/rcu.c',
    'proc/sched.c',
    'proc/signal.c',
    'sys/eventqueue.c',
    'sys/exec.c',
    'sys/filesystem.c',
    'sys/handle.c',
    'sys/hydrogen.c',
    'sys/memory.c',
    'sys/process.c',
    'sys/syscall.c',
    'sys/thread.c',
    'sys/time.c',
    'sys/transition.c',
    'sys/vdso.c',
    'util/eventqueue.c',
    'util/handle.c',
    'util/object.c',
    'util/panic.c',
    'util/printk.c',
    'util/spinlock.c',
    'util/time.c',
)

linker_script = files('kernel.lds')[0]

strip_ver_out = run_command(strip, '--version', capture: true, check: false)
strip_args = []

if strip_ver_out.returncode() == 0
    if strip_ver_out.stdout().contains('GNU Binutils')
        strip_args += ['--strip-section-headers']
    elif strip_ver_out.stdout().contains('LLVM')
        strip_args += ['--strip-sections']
    endif
endif

stripped_vdso = custom_target(
    'stripped-vdso',
    command: [strip, '@INPUT@', '-o@OUTPUT@', strip_args],
    input: vdso,
    output: 'stripped-vdso.so',
)
vdso_object = custom_target(
    'vdso-object',
    command: [objcopy, '@INPUT@', '@OUTPUT@', '-Ibinary', '-O' + bfd_elf_name, '--rename-section=.data=.vdso'],
    input: stripped_vdso,
    output: 'vdso.o',
)

executable(
    'hydrogen',
    c_args: kernel_c_flags,
    implicit_include_directories: false,
    include_directories: [inc, kernel_include],
    install: true,
    install_dir: '/boot',
    install_mode: 'rw-r--r--',
    link_args: [kernel_l_flags, '-T' + linker_script.full_path()],
    link_depends: linker_script,
    objects: vdso_object,
    sources: [lib_sources, kernel_sources],
)
