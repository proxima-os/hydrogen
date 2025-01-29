#include "hydrogen/memory.h"
#include "compiler.h"
#include "sys/sysvecs.h"
#include "syscall.h"
#include <cpuid.h>
#include <stdint.h>

intptr_t hydrogen_map_memory(uintptr_t preferred, size_t size, int flags, int fd, uint64_t offset) {
    syscall_result_t result = syscall5(SYS_MMAP, preferred, size, flags, fd, offset);
    return unlikely(result.error) ? -result.error : (intptr_t)result.value.num;
}

int hydrogen_set_memory_protection(uintptr_t start, size_t size, int flags) {
    return syscall3(SYS_MPROTECT, start, size, flags).error;
}

int hydrogen_unmap_memory(uintptr_t start, size_t size) {
    return syscall2(SYS_MUNMAP, start, size).error;
}

static uintptr_t sys_get_fs_base(void) {
    return syscall0(SYS_GET_FS_BASE).value.num;
}

static uintptr_t rdfsbase(void) {
    uintptr_t value;
    asm volatile("rdfsbase %0" : "=r"(value));
    return value;
}

static uintptr_t (*resolve_gfsb(void))(void) {
    unsigned eax, ebx, ecx, edx;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) return sys_get_fs_base;
    return eax & bit_FSGSBASE ? rdfsbase : sys_get_fs_base;
}

uintptr_t hydrogen_get_fs_base(void) __attribute__((ifunc("resolve_gfsb")));

static uintptr_t sys_get_gs_base(void) {
    return syscall0(SYS_GET_GS_BASE).value.num;
}

static uintptr_t rdgsbase(void) {
    uintptr_t value;
    asm volatile("rdgsbase %0" : "=r"(value));
    return value;
}

static uintptr_t (*resolve_ggsb(void))(void) {
    unsigned eax, ebx, ecx, edx;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) return sys_get_gs_base;
    return eax & bit_FSGSBASE ? rdgsbase : sys_get_gs_base;
}

uintptr_t hydrogen_get_gs_base(void) __attribute__((ifunc("resolve_ggsb")));

static int sys_set_fs_base(uintptr_t value) {
    return syscall1(SYS_GET_FS_BASE, value).error;
}

static int wrfsbase(uintptr_t value) {
    asm("wrfsbase %0" ::"r"(value));
    return 0;
}

static int (*resolve_sfsb(void))(uintptr_t) {
    unsigned eax, ebx, ecx, edx;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) return sys_set_fs_base;
    return eax & bit_FSGSBASE ? wrfsbase : sys_set_fs_base;
}

int hydrogen_set_fs_base(uintptr_t) __attribute__((ifunc("resolve_sfsb")));

static int sys_set_gs_base(uintptr_t value) {
    return syscall1(SYS_GET_GS_BASE, value).error;
}

static int wrgsbase(uintptr_t value) {
    asm("wrgsbase %0" ::"r"(value));
    return 0;
}

static int (*resolve_sgsb(void))(uintptr_t) {
    unsigned eax, ebx, ecx, edx;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) return sys_set_gs_base;
    return eax & bit_FSGSBASE ? wrgsbase : sys_set_gs_base;
}

int hydrogen_set_gs_base(uintptr_t) __attribute__((ifunc("resolve_sgsb")));
