ENTRY(_entry)

PHDRS {
    rodata PT_LOAD FLAGS(4);
    text   PT_LOAD FLAGS(5);
    data   PT_LOAD FLAGS(6);
}

NOCROSSREFS_TO(.init.text .rodata .text .data .vdso .bss)
NOCROSSREFS_TO(.init.data .rodata .text .data .vdso .bss)
NOCROSSREFS_TO(.cmdline .rodata .text .data .vdso .bss)
NOCROSSREFS_TO(.inittask.early .rodata .text .data .vdso .bss)
NOCROSSREFS_TO(.inittask.earlyap .rodata .text .data .vdso .bss)
NOCROSSREFS_TO(.inittask.dflt .rodata .text .data .vdso .bss)
NOCROSSREFS_TO(.inittask.deftap .rodata .text .data .vdso .bss)

SECTIONS {
    . = 0xffffffff80000000;
    _start = .;

    .requests : { KEEP(*(SORT_BY_NAME(.requests*))) } :rodata
    .rodata : { *(.rodata .rodata.*) } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    _erodata = .;
    .text : { *(.text .text.*) } :text
    .cleanup.text : { *(.cleanup.text) } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .init.text : {
        __init_text_start = .;
        *(.init.text)
        . = ALIGN(CONSTANT(MAXPAGESIZE));
        __init_text_end = .;
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    _etext = .;
    .data : { *(.data .data.*) } :data

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .init.data : {
        __init_data_start = .;
        *(.init.data)
    } :data

    .cmdline : { __cmdline_start = .; KEEP(*(SORT_BY_NAME(.cmdline.*))) __cmdline_end = .; } :data
    .inittask.early : { __inittask_start_early = .; KEEP(*(.inittask.early)) __inittask_end_early = .; } :data
    .inittask.earlyap : { __inittask_start_earlyap = .; KEEP(*(.inittask.earlyap)) __inittask_end_earlyap = .; } :data
    .inittask.dflt : { __inittask_start_dflt = .; KEEP(*(.inittask.dflt)) __inittask_end_dflt = .; } :data
    .inittask.dfltap : { __inittask_start_dfltap = .; KEEP(*(.inittask.dfltap)) __inittask_end_dfltap = .; } :data

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __init_data_end = .;

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .vdso : {
        __vdso_start = .;
        vdso_info = .;
        . += CONSTANT(MAXPAGESIZE);
        vdso_image = .;
        KEEP(*(.vdso))
        . = ALIGN(CONSTANT(MAXPAGESIZE));
        __vdso_end = .;
    } :data

    .bss : { *(.bss .bss.*) } :data

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    _end = .;

    /DISCARD/ : { *(.eh_frame* .note*) }
}
