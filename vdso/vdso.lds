VERSION {
    {
    global:
        hydrogen_thread_exit;
        hydrogen_log_write;
        hydrogen_get_time;
        hydrogen_namespace_create;
        hydrogen_handle_create;
        hydrogen_handle_close;
        hydrogen_page_size;
        hydrogen_vm_create;
        hydrogen_vm_clone;
        hydrogen_vm_map;
        hydrogen_vm_map_vdso;
        hydrogen_vm_remap;
        hydrogen_vm_unmap;
        hydrogen_io_enable;
        hydrogen_io_disable;
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
