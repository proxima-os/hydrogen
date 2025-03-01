#pragma once

#include <stdint.h>

typedef struct {
    uint8_t ident[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t phoff;
    uint64_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} elf_header_t;

#define ELF_CLASS 2
#define ELF_DATA 1
#define ELF_VERSION 1
#define ELF_MACHINE 62

#define ET_EXEC 2
#define ET_DYN 3

typedef struct {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
} elf_segment_t;

#define PT_LOAD 1
#define PT_INTERP 3
#define PT_PHDR 6

#define PF_X 1
#define PF_W 2
#define PF_R 4

typedef struct {
    intptr_t tag;
    uintptr_t value;
} elf_auxv_t;

#define AT_NULL 0
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_BASE 7
#define AT_ENTRY 9
#define AT_SYSINFO_EHDR 33
