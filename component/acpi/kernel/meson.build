uacpi = subproject('uacpi')

kernel_c_flags += ['-DUACPI_BAREBONES_MODE', '-DUACPI_SIZED_FREES']
kernel_include += uacpi.get_variable('includes')
kernel_sources += uacpi.get_variable('sources')

kernel_include += include_directories('include')
kernel_sources += files('acpi.c')
