project(
    'hydrogen',
    'c',
    default_options: ['c_std=gnu11', 'warning_level=2'],
    license: 'MIT',
    license_files: 'LICENSE',
    meson_version: '>=1.1.0',
    version: '0.1.0',
)

compiler = meson.get_compiler('c')
objcopy = find_program('objcopy')
strip = find_program('strip')

api_inc = include_directories('include/public')
priv_inc = include_directories('include/private')

add_project_arguments(
    '-DLIMINE_API_REVISION=2',
    '-DUACPI_OVERRIDE_LIBC',
    '-DUACPI_SIZED_FREES',
    '-fno-common',
    language: 'c',
)

if get_option('qemu_debugcon')
    add_project_arguments('-DHYDROGEN_DEBUGCON=1', language: 'c')
endif

uacpi = subproject('uacpi')

subdir('lib')
subdir('vdso')
subdir('kernel')

install_headers(
    'include/public/hydrogen/dirent.h',
    'include/public/hydrogen/error.h',
    'include/public/hydrogen/fcntl.h',
    'include/public/hydrogen/limits.h',
    'include/public/hydrogen/memory.h',
    'include/public/hydrogen/sched.h',
    'include/public/hydrogen/stat.h',
    'include/public/hydrogen/time.h',
    'include/public/hydrogen/vfs.h',
    subdir: 'hydrogen',
)

hydrogen_dep = declare_dependency(include_directories: api_inc, link_with: vdso)
meson.override_dependency('hydrogen', hydrogen_dep)

pkg = import('pkgconfig')
pkg.generate(
    vdso,
    description: 'Headers and libraries needed to interface with the Hydrogen kernel',
    filebase: 'hydrogen'
)
