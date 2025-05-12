vdso_include += include_directories('include')
vdso_sources += files(
    'assert.c',
    'eventqueue.c',
    'handle.c',
    'memory.c',
    'process.c',
    'start.c',
    'thread.c',
    'time.c',
)

linker_script = files('vdso.lds')[0]

vdso = shared_library(
    'hydrogen',
    gnu_symbol_visibility: 'hidden',
    implicit_include_directories: false,
    include_directories: [inc, vdso_include],
    install: true,
    install_tag: 'devel', # the vDSO is provided in memory by the kernel, the copy on disk is only for linking programs
    link_args: ['-T' + linker_script.full_path(), '-Wl,-Bsymbolic'],
    link_depends: files('vdso.lds'),
    sources: [lib_sources, vdso_sources],
)
