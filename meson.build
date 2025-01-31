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

subdir('lib')
subdir('kernel')
