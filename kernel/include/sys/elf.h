#pragma once

#include <stdint.h>

typedef struct {
    uint8_t ident[16];
    uint16_t image_type;
    uint16_t machine;
    uint32_t version;
    uintptr_t entry;
    uintptr_t phoff;
    uintptr_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} __attribute__((packed)) elf_header_t;

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFCLASS64 2
#define ELFDATA2LSB 1

#define ET_EXEC 2
#define ET_DYN 3

#define EM_NATIVE 62
#define EV_CURRENT 1

typedef struct {
    uint32_t kind;
    uint32_t flags;
    uintptr_t offset;
    uintptr_t vaddr;
    uintptr_t paddr;
    uintptr_t filesz;
    uintptr_t memsz;
    uintptr_t align;
} __attribute__((packed)) elf_segment_t;

#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_PHDR 6

#define PF_X 1
#define PF_W 2
#define PF_R 4

typedef struct {
    long a_type;
    union {
        long a_val;
        void *a_ptr;
        void (*a_fnc)();
    };
} __attribute__((aligned(1))) elf_auxv_t;

#define AT_NULL 0
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_BASE 7
#define AT_ENTRY 9
#define AT_SYSINFO_EHDR 33
