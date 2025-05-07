kernel_c_flags += ['-mcmodel=kernel', '-mgeneral-regs-only', '-mno-red-zone']
kernel_include += include_directories('include')
kernel_sources += files(
    'cpu/cpu.c',
    'cpu/idt.c',
    'cpu/idt.S',
    'cpu/lapic.c',
    'cpu/mca.c',
    'cpu/smp.c',
    'cpu/smp.S',
    'cpu/xsave.c',
    'drv/debugcon.c',
    'drv/ioapic.c',
    'init/main.c',
    'init/main.S',
    'mem/usercopy.c',
    'mem/usercopy.S',
    'proc/sched.c',
    'proc/sched.S',
    'time/hpet.c',
    'time/kvmclock.c',
    'time/time.c',
    'time/tsc.c',
)
