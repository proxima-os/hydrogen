#pragma once

#include "arch/elf.h"
#include <stdint.h>

#define ELFCLASS32 1
#define ELFCLASS64 2

#if ELFCLASSNATIVE == ELFCLASS64
typedef uint64_t elf_size_t;
#elif ELFCLASSNATIVE == ELFCLASS32
typedef uint32_t elf_size_t;
#else
#error "Unknown native ELF class"
#endif

#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ELFDATANATIVE ELFDATA2LSB
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ELFDATANATIVE ELFDATA2MSB
#else
#error "Unsupported native byte order"
#endif

typedef struct {
    uint8_t ident[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    elf_size_t entry;
    elf_size_t phoff;
    elf_size_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} elf_header_t;

#define ET_EXEC 2
#define ET_DYN 3

#define EV_CURRENT 1

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

typedef struct {
    uint32_t type;
#if ELFCLASSNATIVE == ELFCLASS64
    uint32_t flags;
#endif
    elf_size_t offset;
    elf_size_t vaddr;
    elf_size_t paddr;
    elf_size_t filesz;
    elf_size_t memsz;
#if ELFCLASSNATIVE == ELFCLASS32
    uint32_t flags;
#endif
    elf_size_t align;
} elf_phdr_t;

#define PT_LOAD 1
#define PT_INTERP 3
#define PT_PHDR 6

#define PF_X 1
#define PF_W 2
#define PF_R 4
