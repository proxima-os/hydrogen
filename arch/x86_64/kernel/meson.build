inc += include_directories('private')

kernel_c_flags += ['-mcmodel=kernel', '-mgeneral-regs-only', '-mno-red-zone']
kernel_include += include_directories('include')
kernel_sources += files(
    'cpu/cpu.c',
    'cpu/idt.c',
    'cpu/idt.S',
    'cpu/mca.c',
    'drv/debugcon.c',
    'init/main.c',
    'init/main.S',
    'proc/sched.c',
    'proc/sched.S',
)
