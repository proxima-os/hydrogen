ENTRY(_entry)

PHDRS {
    rodata PT_LOAD FLAGS(4);
    text   PT_LOAD FLAGS(5);
    data   PT_LOAD FLAGS(6);
}

SECTIONS {
    . = 0xffffffff80000000;
    _start = .;

    .requests : { KEEP(*(SORT_BY_NAME(.requests*))) } :rodata
    .rodata : { *(.rodata .rodata.*) } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    _erodata = .;
    .text : { *(.text .text.*) } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    _etext = .;
    .data : { *(.data .data.*) } :data

    .cmdline : { __cmdline_start = .; KEEP(*(SORT_BY_NAME(.cmdline.*))) __cmdline_end = .; } :data
    .inittask.early : { __inittask_start_early = .; KEEP(*(.inittask.early)) __inittask_end_early = .; } :data
    .inittask.earlyap : { __inittask_start_earlyap = .; KEEP(*(.inittask.earlyap)) __inittask_end_earlyap = .; } :data
    .inittask.dflt : { __inittask_start_dflt = .; KEEP(*(.inittask.dflt)) __inittask_end_dflt = .; } :data
    .inittask.dfltap : { __inittask_start_dfltap = .; KEEP(*(.inittask.dfltap)) __inittask_end_dfltap = .; } :data

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
