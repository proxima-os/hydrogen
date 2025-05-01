kernel_include += include_directories('include')
kernel_sources += files(
    'init/main.c',
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
