vdso = shared_library(
    'hydrogen',
    'handle.c',
    'io.c',
    'log.c',
    'memory.c',
    'thread.c',
    'time.c',
    c_args: ['-ffreestanding', '-fno-stack-check', '-fno-stack-protector'],
    gnu_symbol_visibility: 'protected',
    implicit_include_directories: false,
    include_directories: [pub_inc, priv_inc],
    install: true,
    install_tag: 'devel', # the vDSO is provided in memory by the kernel, the copy on disk is only for linking programs
    link_args: ['-nostdlib', '-T' + (meson.current_source_dir() / 'vdso.lds')],
    link_depends: files('vdso.lds'),
    sources: lib_sources,
    soversion: 1, # use a constant soversion to make sure the soname is always libhydrogen.so.1
)
