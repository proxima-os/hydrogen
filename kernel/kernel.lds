ENTRY(_entry)

PHDRS {
    rodata PT_LOAD FLAGS(4);
    text   PT_LOAD FLAGS(5);
    data   PT_LOAD FLAGS(6);
}

SECTIONS {
    . = 0xffffffff80000000;
    _start = .;

    .rodata : {
        KEEP(*(SORT_BY_NAME(.requests*)))
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    _erodata = .;
    .text : { *(.text .text.*) } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    _etext = .;
    .data : { *(.data .data.*) } :data

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
