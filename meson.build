project(
    'hydrogen',
    'c',
    default_options: ['c_std=gnu11', 'warning_level=2'],
    license: 'MIT',
    license_files: 'LICENSE',
    meson_version: '>=1.4.0',
    version: '0.1.0',
)

pkg = import('pkgconfig')

objcopy = find_program('objcopy')
strip = find_program('strip')

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
vdso_sources = []
vdso_include = []
vdso_config_data = configuration_data()

wanted_components = []

add_project_arguments('-DHYDROGEN_LOG_BUF_SHIFT=' + get_option('log_buf_shift').to_string(), language: 'c')

subdir('public')
subdir('arch' / host_machine.cpu_family())

foreach component : wanted_components
    subdir('component' / component)
endforeach

subdir('lib')
subdir('vdso')
subdir('kernel')

pkg.generate(vdso, description: 'System calls for the Hydrogen kernel')
