kernel_c_flags += ['-DLIMINE_API_REVISION=3']
kernel_include += include_directories('include')
kernel_sources += files(
    'cpu/cpudata.c',
    'cpu/smp.c',
    'init/cmdline.c',
    'init/main.c',
    'mem/memmap.c',
    'proc/event.c',
    'proc/rcu.c',
    'proc/sched.c',
    'util/panic.c',
    'util/printk.c',
    'util/spinlock.c',
)

linker_script = files('kernel.lds')[0]

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
    sources: [lib_sources, kernel_sources],
)
