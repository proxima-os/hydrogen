linker_script = meson.current_source_dir() / 'vdso.lds'

vdso = shared_library(
    'hydrogen',
    'sched.c',
    'vfs.c',
    c_args: ['-ffreestanding', '-fno-stack-check', '-fno-stack-protector'],
    implicit_include_directories: false,
    include_directories: [api_inc, priv_inc],
    install: true,
    install_tag: 'devel', # the vDSO is provided in memory by the kernel, the copy on disk is only for linking programs
    link_args: ['-nostdlib', '-T' + linker_script],
    link_depends: linker_script,
    sources: lib_sources,
)
