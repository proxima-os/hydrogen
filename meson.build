project(
    'hydrogen',
    'c',
    default_options: ['c_std=gnu11', 'warning_level=2'],
    license: 'MIT',
    license_files: 'LICENSE',
    meson_version: '>=1.1.0',
    version: '0.1.0',
)

pub_inc = include_directories('include' / 'public')
priv_inc = include_directories('include' / 'private')

add_project_arguments('-DHYDROGEN_LOG_BUF_SHIFT=' + get_option('log_buf_shift').to_string(), language: 'c')

if get_option('qemu_debugcon')
    add_project_arguments('-DHYDROGEN_QEMU_DEBUGCON=1', language: 'c')
endif

subdir('lib')
subdir('kernel')
