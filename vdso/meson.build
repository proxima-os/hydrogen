linker_script = meson.current_source_dir() / 'vdso.lds'

vdso = shared_library(
    'hydrogen',
    'memory.c',
    'sched.c',
    'time.c',
    'vfs.c',
    c_args: ['-ffreestanding', '-fno-stack-check', '-fno-stack-protector'],
    implicit_include_directories: false,
    include_directories: [compiler_include_dirs, api_inc, priv_inc],
    install: true,
    install_tag: 'devel', # the vDSO is provided in memory by the kernel, the copy on disk is only for linking programs
    link_args: ['-nostdlib', '-T' + linker_script],
    link_depends: linker_script,
    sources: lib_sources,
    soversion: 1, # use a constant soversion to make sure the soname is always libhydrogen.so.1
)
