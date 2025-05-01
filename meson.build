project(
    'hydrogen',
    'c',
    default_options: ['c_std=gnu11', 'warning_level=2'],
    license: 'MIT',
    license_files: 'LICENSE',
    meson_version: '>=1.4.0',
    version: '0.1.0',
)

objcopy = find_program('objcopy')

inc = [include_directories('private', 'public')]

add_project_arguments(
    '-ffreestanding',
    '-fno-stack-check',
    '-fno-stack-protector',
    '-Wno-unused-parameter',
    language: 'c'
)
add_project_link_arguments('-nostdlib', language: 'c')

lib_sources = []
kernel_c_flags = ['-fno-asynchronous-unwind-tables', '-fno-pie']
kernel_l_flags = ['-static']
kernel_sources = []
kernel_include = []

add_project_arguments('-DHYDROGEN_LOG_BUF_SHIFT=' + get_option('log_buf_shift').to_string(), language: 'c')

subdir('public')
subdir('arch' / host_machine.cpu_family())
subdir('lib')
subdir('kernel')
