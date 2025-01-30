executable(
    'hydrogen',
    'src/init/main.c',
    'src/init/main.S',
    c_args: [
        '-ffreestanding',
        '-fno-pie',
        '-fno-stack-check',
        '-fno-stack-protector',
        '-mcmodel=kernel',
        '-mgeneral-regs-only',
        '-mno-red-zone',
    ],
    implicit_include_directories: false,
    include_directories: [
        pub_inc,
        priv_inc,
        include_directories('include'),
    ],
    install: true,
    install_dir: '/boot',
    link_args: ['-nostdlib', '-static', '-T' + (meson.current_source_dir() / 'kernel.lds')],
    link_depends: files('kernel.lds'),
)
