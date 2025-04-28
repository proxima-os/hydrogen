VERSION {
    {
    global:
        __hydrogen_thread_exit;
        __hydrogen_log_write;
        __hydrogen_get_time;
        __hydrogen_namespace_create;
        __hydrogen_handle_create;
        __hydrogen_handle_close;
        __hydrogen_page_size;
        __hydrogen_vm_create;
        __hydrogen_vm_clone;
        __hydrogen_vm_map;
        __hydrogen_vm_map_vdso;
        __hydrogen_vm_remap;
        __hydrogen_vm_unmap;
        __hydrogen_io_enable;
        __hydrogen_io_disable;
    local: *;
    };
}

PHDRS {
    text    PT_LOAD FILEHDR PHDRS FLAGS(5);
    dynamic PT_DYNAMIC FLAGS(4);
}

SECTIONS {
    HIDDEN(vdso_info = . - CONSTANT(MAXPAGESIZE));

    . = SIZEOF_HEADERS;
    .hash          : { *(.hash) } :text
    .gnu.hash      : { *(.gnu.hash) }
    .dynsym        : { *(.dynsym) }
    .dynstr        : { *(.dynstr) }
    .gnu.version   : { *(.gnu.version) }
    .gnu.version_d : { *(.gnu.version_d) }
    .gnu.version_r : { *(.gnu.version_r) }
    .dynamic       : { *(.dynamic) } :text :dynamic
    .rodata        : { *(.rodata .rodata.*) } :text
    .rel           : { *(.rel .rel.* .rela .rela.*) }
    .text          : { *(.text .text.*) }
    .data          : { *(.bss .bss.* .data .data.* .got .got.*) }

    ASSERT(SIZEOF(.data) == 0, "vdso contains writable data section")
    ASSERT(SIZEOF(.rel) == 0, "vdso contains relocations")

    /DISCARD/ : { *(.eh_frame* .note*) }
}
