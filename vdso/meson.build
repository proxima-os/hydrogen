vdso_config_data.set_quoted('HYDROGEN_RELEASE', meson.project_version())
vdso_config_data.set_quoted('HYDROGEN_VERSION', '@VCS_TAG@')

vdso_config = vcs_tag(
    input: configure_file(configuration: vdso_config_data, output: 'vdso-config.h.in'),
    output: 'vdso-config.h',
)

vdso_include += include_directories('include')
vdso_sources += files(
    'assert.c',
    'eventqueue.c',
    'filesystem.c',
    'handle.c',
    'hydrogen.c',
    'memory.c',
    'process.c',
    'thread.c',
    'time.c',
)

linker_script = files('vdso.lds')[0]

vdso = shared_library(
    'hydrogen',
    vdso_config,
    gnu_symbol_visibility: 'hidden',
    include_directories: [inc, vdso_include],
    install: true,
    install_tag: 'devel', # the vDSO is provided in memory by the kernel, the copy on disk is only for linking programs
    link_args: ['-T' + linker_script.full_path()],
    link_depends: files('vdso.lds'),
    sources: [lib_sources, vdso_sources],
)
